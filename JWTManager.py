import threading
import time
import uuid
from collections import OrderedDict
import jwt

class JWTLoginManager:
    def __init__(self, secret_key, expire_seconds, max_logins, max_per_user):
        self.secret_key = secret_key
        self.expire_seconds = expire_seconds
        self.max_logins = max_logins
        self.max_per_user = max_per_user

        self.login_store = OrderedDict()  # jti -> (user_id, issued_at timestamp)
        self.user_jtis_map = {}           # user_id -> set of jti
        self._lock = threading.Lock()

        self._clean_call_count = 0
        self._clean_call_threshold = min(64, max_logins)
        self._last_reorder_time = time.monotonic()
        self._reorder_interval_seconds = 1800

    # ----------------- 私有方法 -----------------

    def _is_expired(self, issued_at):
        return time.monotonic() - issued_at > self.expire_seconds

    def _remove_token_entry(self, jti):
        info = self.login_store.pop(jti, None)
        if info is None:
            return
        user_id, _ = info
        if user_id in self.user_jtis_map:
            self.user_jtis_map[user_id].discard(jti)
            if not self.user_jtis_map[user_id]:
                self.user_jtis_map.pop(user_id)

    def _remove_oldest_token_of_user(self, user_id):
        if user_id not in self.user_jtis_map or not self.user_jtis_map[user_id]:
            return False
        user_jtis = self.user_jtis_map[user_id]
        user_tokens = [(jti, self.login_store[jti][1]) for jti in user_jtis if jti in self.login_store]
        if not user_tokens:
            return False
        oldest_jti = sorted(user_tokens, key=lambda x: x[1])[0][0]
        self._remove_token_entry(oldest_jti)
        return True

    def _clean_expired_until_first_valid(self):
        keys_to_remove = []
        for jti, (_, issued_at) in self.login_store.items():
            if self._is_expired(issued_at):
                keys_to_remove.append(jti)
            else:
                break
        for jti in keys_to_remove:
            self._remove_token_entry(jti)

        # 触发重排
        now = time.monotonic()
        self._clean_call_count += 1
        if self._clean_call_count >= self._clean_call_threshold or now - self._last_reorder_time >= self._reorder_interval_seconds:
            self._clean_call_count = 0
            self._last_reorder_time = now
            items = []
            for jti, (user_id, issued_at) in self.login_store.items():
                if issued_at + self.expire_seconds <= now:
                    if user_id in self.user_jtis_map:
                        self.user_jtis_map[user_id].discard(jti)
                        if not self.user_jtis_map[user_id]:
                            self.user_jtis_map.pop(user_id)
                    continue
                fixed_issued_at = issued_at if issued_at <= now else now
                items.append((jti, (user_id, fixed_issued_at)))
            self.login_store.clear()
            for jti, value in sorted(items, key=lambda x: x[1][1]):
                self.login_store[jti] = value

    def _add_token_for_user(self, user_id):
        jti = str(uuid.uuid4())
        issued_at = time.monotonic()
        token = jwt.encode({ 'jti': jti }, self.secret_key, algorithm='HS256')
        self.login_store[jti] = (user_id, issued_at)
        self.user_jtis_map.setdefault(user_id, set()).add(jti)
        return token

    def _extract_valid_token_info(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            jti = payload.get('jti')
            if not jti:
                return None, "Invalid token payload"
            info = self.login_store.get(jti)
            if info is None:
                return None, "Token not found or already logged out"
            user_id, issued_at = info
            return {
                'jti': jti,
                'user_id': user_id,
                'issued_at': issued_at
            }, None
        except jwt.InvalidTokenError:
            return None, "Invalid token"

    # ----------------- 公开方法 -----------------

    def generate_token(self, user_id):
        with self._lock:
            if user_id in self.user_jtis_map and len(self.user_jtis_map[user_id]) >= self.max_per_user:
                removed = self._remove_oldest_token_of_user(user_id)
                if not removed:
                    return None, "User max login limit reached"

            if len(self.login_store) >= self.max_logins:
                self._clean_expired_until_first_valid()
                if len(self.login_store) >= self.max_logins:
                    return None, "Global max login limit reached"

            return self._add_token_for_user(user_id), None

    def verify_token(self, token):
        with self._lock:
            info, err = self._extract_valid_token_info(token)
            if not info:
                return False, err

            if self._is_expired(info['issued_at']):
                self._remove_token_entry(info['jti'])
                return False, "Token expired"

            return True, info['user_id']

    def refresh_token(self, old_token):
        with self._lock:
            info, err = self._extract_valid_token_info(old_token)
            if not info:
                return None, err

            if self._is_expired(info['issued_at']):
                self._remove_token_entry(info['jti'])
                return None, "Token expired"

            self._remove_token_entry(info['jti'])

            return self._add_token_for_user(info['user_id']), None

    def logout_token(self, token):
        with self._lock:
            info, err = self._extract_valid_token_info(token)
            if not info:
                return False, err
            self._remove_token_entry(info['jti'])
            return True, "Logout successful"

    def logout_user(self, user_id):
        with self._lock:
            if user_id not in self.user_jtis_map:
                return False, "User has no active tokens"
            for jti in list(self.user_jtis_map[user_id]):
                self._remove_token_entry(jti)
            return True, "User logged out"