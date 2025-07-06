import threading
import datetime
import uuid
import jwt

#dict保持插入顺序才能正常工作
class JWTLoginManager:
    def __init__(self, secret_key, expire_seconds, max_users, max_user_logins):
        self.secret_key = secret_key
        self.expire_seconds = expire_seconds
        self.max_users = max_users
        self.max_user_logins = max_user_logins

        self.login_store = {}       # jti -> (user_id, issued_at timestamp)
        self.index_user = {}       # user_id -> set of jti
        self._lock = threading.Lock()

    # ----------------- 私有方法 -----------------

    def _current_second(self):
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    def _is_expired(self, issued_at):
        return self._current_second() - issued_at > self.expire_seconds

    def _remove_token_entry(self, jti):
        info = self.login_store.pop(jti, None)
        if info is None:
            return
        user_id, _ = info
        if user_id in self.index_user:
            self.index_user[user_id].pop(jti, None)
            if not self.index_user[user_id]:
                self.index_user.pop(user_id)

    def _remove_oldest_token_of_user(self, user_id):
        if user_id not in self.index_user or not self.index_user[user_id]:
            return False
        oldest_jti = next(iter(self.index_user[user_id]))
        self._remove_token_entry(oldest_jti)
        return True

    def _clean_expired(self):
        keys_to_remove = []
        for jti, (_, issued_at) in self.login_store.items():
            if self._is_expired(issued_at):
                keys_to_remove.append(jti)
            else:
                break
        for jti in keys_to_remove:
            self._remove_token_entry(jti)

    def _add_token_for_user(self, user_id):
        jti = str(uuid.uuid4())
        issued_at = self._current_second()
        token = jwt.encode({ 'jti': jti }, self.secret_key, algorithm='HS256')
        self.login_store[jti] = (user_id, issued_at)
        self.index_user.setdefault(user_id, {})[jti] = None
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
            self._clean_expired()

            if user_id not in self.index_user and len(self.index_user) >= self.max_users:
                return None, "Global max user limit reached"
            
            if user_id in self.index_user and len(self.index_user[user_id]) >= self.max_user_logins:
                removed = self._remove_oldest_token_of_user(user_id)
                if not removed:
                    return None, "User max login limit reached"
                
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
            if user_id not in self.index_user:
                return False, "User has no active tokens"
            for jti in list(self.index_user[user_id]):
                self._remove_token_entry(jti)
            return True, "User logged out"