import json
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response, Response, stream_with_context
import bcrypt
import datetime
import MySQLdb
import base64
from JWTManager import JWTLoginManager, JWTAuthManager
from threading import Timer
from collections import deque
import threading
import queue
import uuid
import jwt

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

load_dotenv()

app = Flask(__name__)

# JWT设置
JWT_SECRET = os.getenv('JWT_SECRET')    # 用于生成token的密钥
JWT_EXPIRE_SECONDS = min(max(300, int(os.getenv('JWT_EXPIRE_SECONDS', 600))), 1800)    # token有效秒
JWT_AUTH_EXPIRE_SECONDS = min(max(5, int(os.getenv('JWT_AUTH_EXPIRE_SECONDS', 10))), 30)

# 其他设置
MAX_AUTH = min(max(1, int(os.getenv('MAX_AUTH', 16))), 64)
MAX_USERS = min(max(1, int(os.getenv('MAX_USERS', 8))), 16)
MAX_USER_LOGINS = min(max(1, int(os.getenv('MAX_USER_LOGINS', 1))), 4)
EMPLOYEE_CLOTH_EXPIRE_SECONDS = min(max(300, int(os.getenv('EMPLOYEE_CLOTH_EXPIRE_SECONDS', 600))), 1800)    #超出秒数后员工不可修改提交数据
PRINTER_EXPIRE_SECONDS = min(max(300, int(os.getenv('PRINTER_EXPIRE_SECONDS', 600))), 1800)

# 配置 MySQL 连接
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

printer_lock = threading.Lock()
printer_connected = {'jtis': deque(maxlen=2), 'connected': False}

message_queue = queue.Queue()

jwt_login_manager = JWTLoginManager(JWT_SECRET, JWT_EXPIRE_SECONDS, MAX_USERS, MAX_USER_LOGINS)
jwt_auth_manager = JWTAuthManager(JWT_SECRET, JWT_AUTH_EXPIRE_SECONDS, MAX_AUTH)

# 创建连接
def get_db_connection():
    return MySQLdb.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        passwd=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        charset='utf8mb4'
    )

@app.before_request
def check_login_token():
    # 排除登录接口和其他公开接口
    open_paths = {'/api/login', '/api/login-before', '/api/stream', '/api/printer/login'}
    employee_paths = {
        '/api/logout',
        '/api/check-login',
        '/api/refresh-token',
        '/api/combobox',
        '/api/employee/cloth/add',
        '/api/employee/cloth/query',
        '/api/employee/cloth/update',
        '/api/employee/cloth/print',
        '/api/machine/search'
    }
    if request.path in open_paths:
        return  # 跳过校验
    if request.method == 'OPTIONS':
        return  # 预检请求直接放行
    # 校验 token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401
    
    valid, result = jwt_login_manager.verify_token(token)
    if not valid:
        return jsonify({'error': result}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息
        sql = "SELECT user_id, user_name, is_admin, is_locked, print_allowed FROM sys_user WHERE user_id = %s"
        cursor.execute(sql, (result,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({'error': 'Missing user'}), 401
        
        if int.from_bytes(user['is_admin'], 'big') == 0:
            if int.from_bytes(user['is_locked'], 'big') == 1:
                jwt_login_manager.logout_user(result)
                return jsonify({'error': 'User has been locked'}), 401
            if request.path not in employee_paths:
                return jsonify({'error': 'Insufficient permissions'}), 400

        request.user = user

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/printer/login', methods=['POST'])
def printer_login():
    try:
        with printer_lock:
            if printer_connected['connected']:
                return jsonify({'error': 'already had printer connect'}), 403
        data = request.get_json()
        username = data.get('user_name')
        password = data.get('user_password')
        auth_token = data.get('auth_token')

        if not username or not password or not auth_token:
            return jsonify({'error': 'Username and password and auth_token are required'}), 400

        valid, result = jwt_auth_manager.verify_token(auth_token)
        if not valid:
            return jsonify({'error': result}), 401

        password = decrypt_password(password, result)

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
        sql = "SELECT user_id, user_name, user_password, is_admin, is_locked FROM sys_user WHERE user_name = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and int.from_bytes(user['is_locked'], 'big') == 1 and int.from_bytes(user['is_admin'], 'big') == 0:
            jwt_login_manager.logout_user(user['user_id'])
            return jsonify({'error': 'User has been locked'}), 401
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
            with printer_lock:
                if printer_connected['connected']:
                    return jsonify({'error': 'already had printer connect'}), 403
                token, jti = printer_generate_token()
                return jsonify({'token': token, 'jti': jti}), 201
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

def printer_generate_token():
    jti = str(uuid.uuid4())
    payload = {
        "jti": jti,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=PRINTER_EXPIRE_SECONDS)
    }
    printer_connected['jtis'].append(jti)
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token, jti

def printer_verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        jti = payload.get("jti")
        if jti is None or jti not in printer_connected['jtis']:
            return False
        return True
    except jwt.ExpiredSignatureError:
        return False
    except Exception:
        return False

@app.route('/api/stream')
def stream():
    token = request.headers.get("Authorization")
    if not token:
        return "Missing token", 401
    with printer_lock:
        if printer_connected['connected']:
            return jsonify({'error': 'already had printer connect'}), 403
        if not printer_verify_token(token):
            return "token expried or wrong", 401
        printer_connected['connected'] = True
    def event_stream():
        with printer_lock:
            printer_connected['connected'] = True
        last_refresh = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        try:
            while True:
                # 优先推送消息队列内容
                try:
                    msg = message_queue.get(timeout=5)
                    if msg.get('stop_printer'):
                        with printer_lock:
                            printer_connected['jtis'].clear
                        break
                    if not msg.get('print_label') or not msg.get('print_param'):
                        yield f"data: {json.dumps({'type': 'warning', 'info': 'Invalid message'})}\n\n"
                    else:
                        match msg['print_label']:
                            case 'knit_cloth_print':
                                conn = get_db_connection()
                                cursor = conn.cursor(MySQLdb.cursors.DictCursor)
                                cursor.callproc('knit_cloth_print', [msg['print_param']])
                                sql_data = cursor.fetchone()
                                if cursor.nextset():
                                    qr_data = cursor.fetchone()
                                cursor.close()
                                conn.close()

                                yield f"data: {json.dumps({'type': 'print', 'print_label': 'knit_cloth_print', 'label_data': sql_data, 'qr_data': qr_data}, default=str)}\n\n"

                            case 'knit_delivery_print':
                                conn = get_db_connection()
                                cursor = conn.cursor(MySQLdb.cursors.DictCursor)
                                cursor.callproc('knit_delivery_print', [msg['print_param']])
                                sql_data = cursor.fetchall()
                                cursor.close()
                                conn.close()

                                for page_data in sql_data:
                                    yield f"data: {json.dumps({'type': 'print', 'print_label': 'knit_delivery_print', 'label_data': page_data, 'qr_data': None}, default=str)}\n\n"
                            
                            case _:
                                # 未知标签发送错误
                                yield f"data: {json.dumps({'type': 'warning', 'info': 'Invalid print_label'})}\n\n"
                except queue.Empty:
                    # 队列空发送心跳
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
                except MySQLdb.Error:
                    # sql异常发送错误
                    yield f"data: {json.dumps({'type': 'warning', 'info': 'Sql error'})}\n\n"

                # 定时刷新 token
                now_second = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
                if now_second - last_refresh > PRINTER_EXPIRE_SECONDS / 2:
                    with printer_lock:
                        new_token, new_jti = printer_generate_token()
                    yield f"data: {json.dumps({'type': 'token_refresh', 'token': new_token, 'jit': new_jti})}\n\n"
                    last_refresh = now_second
        finally:
            with printer_lock:
                printer_connected['connected'] = False

    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

# 普通客户端访问此接口，向打印端发送消息
@app.route('/api/send-print', methods=['POST'])
def notify():
    try:
        with printer_lock:
            if not printer_connected['connected']:
                return jsonify({'error': 'printer not connected'}), 403
            
        data = request.get_json()
        stop_printer = data.get('stop_printer')
        if stop_printer:
            message_queue.put({
                'stop_printer': True
            })
        else:
            print_label = data.get('print_label')
            print_param_list = data.get('print_param_list')

            if not print_label or not print_param_list:
                return jsonify({'error': 'Missing required parameters'}), 400
            
            allow_labels = {'knit_cloth_print', 'knit_delivery_print'}

            if print_label not in allow_labels:
                return jsonify({'error': 'Invalid print_label'}), 400
            
            for print_param in print_param_list:
                message_queue.put({
                    'print_label': print_label,
                    'print_param': print_param
                })

        return jsonify({'status': 'ok'}), 202
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_str = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key_str

def decrypt_password(encrypted_b64: str, private_key) -> str:
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_bytes.decode('utf-8')

@app.route('/api/employee/cloth/query', methods=['POST'])
def employee_cloth_query_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'cloth_id': 'A.cloth_id',
            'order_no': 'B.order_no',
            'order_cloth_name': 'B.order_cloth_name',
            'order_cloth_color': 'B.order_cloth_color',
            'machine_name': 'C.machine_name',
        }
        allowed_date_range_fields = {
            'add_time': 'A.add_time',
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        params[:0] = [request.user['user_id']]

        # 查询数据
        query_sql = f"""
        select A.cloth_id, A.cloth_origin_weight, A.cloth_weight_correct, A.add_time, A.edit_time, A.note, 
        B.order_no, B.order_cloth_name, B.order_cloth_color, B.order_cloth_add, 
        C.machine_name, 
        E.user_name AS add_user_name, 
        (A.cloth_origin_weight + COALESCE(B.order_cloth_add, 0) + COALESCE(A.cloth_weight_correct, 0)) AS cloth_calculate_weight, 
        A.cloth_order_id, A.cloth_machine_id, A.add_user_id
        from knit_cloth A
        left join knit_order B on A.cloth_order_id = B.order_id
        left join knit_machine C on A.cloth_machine_id = C.machine_id
        join sys_user E on E.user_id = %s and A.add_user_id = E.user_id
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        select COUNT(*) as total
        from knit_cloth A
        left join knit_order B on A.cloth_order_id = B.order_id
        left join knit_machine C on A.cloth_machine_id = C.machine_id
        left join sys_user E on E.user_id = %s and A.add_user_id = E.user_id
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/employee/cloth/add', methods=['POST'])
def employee_cloth_add():
    try:
        allowed_fields = { 'cloth_order_id', 'cloth_machine_id', 'cloth_origin_weight', 'cloth_weight_correct', 'note' }
        data = request.get_json()
        json_data = data.get('json_data')

        if not json_data:
            return jsonify({'error': 'Missing json_data'}), 400

        insert_data = {}

        for field, value in json_data.items():
            if field in allowed_fields:
                insert_data[field] = value

        json_str = json.dumps(insert_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.callproc('super_insert', ['knit_cloth', request.user['user_id'], json_str])
        sql_data = cursor.fetchone()
        while cursor.nextset():
            pass
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful', 'insert_id': sql_data['super_insert_id']}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500
    
@app.route('/api/employee/cloth/update', methods=['POST'])
def employee_cloth_update():
    try:
        allowed_fields = { 'cloth_order_id', 'cloth_machine_id', 'cloth_origin_weight', 'cloth_weight_correct', 'note' }
        data = request.get_json()
        pk_value = data.get('pk_value')
        json_data = data.get('json_data')

        if not json_data or not pk_value:
            return jsonify({'error': 'Missing json_data or pk_value'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        sql = "SELECT TIMESTAMPDIFF(SECOND, add_time, NOW()) AS delay_time, add_user_id FROM knit_cloth WHERE cloth_id = %s"
        cursor.execute(sql, (pk_value,))
        searched_cloth = cursor.fetchone()
        cursor.close()
        conn.close()

        if searched_cloth['add_user_id'] != request.user['user_id']:
            return jsonify({'error': 'Not input user'}), 400
        
        if int.from_bytes(request.user['is_admin'], 'big') == 0 and searched_cloth['delay_time'] > EMPLOYEE_CLOTH_EXPIRE_SECONDS:
            return jsonify({'error': 'Time expired'}), 400

        update_data = {}

        for field, value in json_data.items():
            if field in allowed_fields:
                update_data[field] = value

        json_str = json.dumps(update_data, ensure_ascii=False)
        pk_values_json = json.dumps([pk_value], ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('super_update', ['knit_cloth', request.user['user_id'], pk_values_json, json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500    

@app.route('/api/employee/cloth/print', methods=['POST'])
def employee_cloth_print():
    try:
        with printer_lock:
            if not printer_connected['connected']:
                return jsonify({'error': 'printer not connected'}), 403
            
        data = request.get_json()
        pk_value = data.get('pk_value')

        if not pk_value:
            return jsonify({'error': 'Missing pk_value'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        sql = "SELECT add_user_id FROM knit_cloth WHERE cloth_id = %s"
        cursor.execute(sql, (pk_value,))
        searched_cloth = cursor.fetchone()
        cursor.close()
        conn.close()

        if searched_cloth['add_user_id'] != request.user['user_id']:
            return jsonify({'error': 'Not input user'}), 400
        
        if int.from_bytes(request.user['is_admin'], 'big') == 0 and int.from_bytes(request.user['print_allowed'], 'big') == 0:
            return jsonify({'error': 'Print not allowed, please contact the administrator'}), 400

        message_queue.put({
                'print_label': 'knit_cloth_print',
                'print_param': pk_value
            })

        return jsonify({'status': 'ok'}), 202
    
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/delivery/cloth/update', methods=['POST'])
def delivery_cloth_update():
    try:
        data = request.get_json()
        pk_values = data.get('pk_values')
        cloth_operate = data.get('cloth_operate')
        delivery_id = data.get('delivery_id')

        if not cloth_operate or not pk_values or not delivery_id:
            return jsonify({'error': 'Missing required parameters', 'errorType': 0}), 400

        if cloth_operate not in {'out', 'cancel'}:
            return jsonify({'error': 'invalid parameters', 'errorType': 0}), 400

        unique_pk_values = list(set(pk_values))
        placeholders = ','.join(['%s'] * len(unique_pk_values))

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        sql = f"""SELECT B.delivery_id FROM knit_cloth A LEFT JOIN knit_delivery B ON A.cloth_delivery_id = B.delivery_id WHERE A.cloth_id IN ({placeholders})"""
        cursor.execute(sql, unique_pk_values)
        searched_clothes = cursor.fetchall()
        cursor.close()
        conn.close()

        if len(searched_clothes) != len(unique_pk_values):
            return jsonify({'error': 'cloth_id not found or incorrect', 'errorType': 1}), 400

        for row in searched_clothes:
            if row['delivery_id'] is not None and cloth_operate == 'out':
                return jsonify({'error': 'delivery cloth has been out', 'errorType': 2}), 400
            if row['delivery_id'] != delivery_id and cloth_operate == 'cancel':
                return jsonify({'error': 'can not cancel other delivery cloth or inventory cloth', 'errorType': 3}), 400
            

        if cloth_operate == 'out':
            json_str = json.dumps({ 'cloth_delivery_id': delivery_id, 'cloth_delivery_time': 0 }, ensure_ascii=False)
        elif cloth_operate == 'cancel':
            json_str = json.dumps({ 'cloth_delivery_id': None, 'cloth_delivery_time': None }, ensure_ascii=False)
        pk_values_json = json.dumps(pk_values, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('super_update', ['knit_cloth', request.user['user_id'], pk_values_json, json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Update successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500    

@app.route('/api/generic/insert', methods=['POST'])
def insert_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        json_data = data.get('json_data')  # 这里假设客户端传的是一个 dict

        if not table_name or not json_data:
            return jsonify({'error': 'Missing required parameters'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.callproc('super_insert', [table_name, request.user['user_id'], json_str])
        sql_data = cursor.fetchone()
        while cursor.nextset():
            pass
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful', 'insert_id': sql_data['super_insert_id']}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500


@app.route('/api/generic/update', methods=['POST'])
def update_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        pk_values = data.get('pk_values')
        json_data = data.get('json_data')  # 这里假设客户端传的是一个 dict

        if not all([table_name, json_data, pk_values]):
            return jsonify({'error': 'Missing required parameters'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)
        pk_values_json = json.dumps(pk_values, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('super_update', [table_name, request.user['user_id'], pk_values_json, json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Update successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/generic/delete', methods=['POST'])
def delete_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        pk_values = data.get('pk_values')  # 期望是列表或数组

        if not all([table_name, pk_values]):
            return jsonify({'error': 'Missing required parameters'}), 400

        pk_values_json = json.dumps(pk_values, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 调用存储过程
        cursor.callproc('super_delete', [table_name, request.user['user_id'], pk_values_json])
        conn.commit()

        affected_rows = cursor.rowcount  # 受影响行数，有时可能不准确，视 MySQL 版本

        cursor.close()
        conn.close()

        return jsonify({'message': 'Delete successful', 'affected_rows': affected_rows})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/combobox', methods=['GET'])
def get_combobox_values():
    try:
        table_name = request.args.get('table_name')
        table_field_name = request.args.get('table_field_name')

        if not table_name or not table_field_name:
            return jsonify({'error': 'Missing table_name or table_field_name'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        sql = """
        SELECT table_field_value, table_field_label
        FROM combobox_value
        WHERE table_name = %s AND table_field_name = %s
        ORDER BY table_field_value
        """
        cursor.execute(sql, (table_name, table_field_name))
        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(rows), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500


def normalize_date_range(date_strs):
    # 将前端传入的 ['2025-06-01', '2025-06-18'] 扩展为完整时间段
    if not isinstance(date_strs, list) or len(date_strs) != 2:
        return None, None
    start_date = date_strs[0] + ' 00:00:00'
    end_date = date_strs[1] + ' 23:59:59'
    return start_date, end_date

def analyze_query_data(allowed_fields, allowed_date_range_fields, data):
    filters = data.get('filters', {})
    fuzzy_fields = data.get('fuzzy_fields', {})
    order_fields = data.get('order_fields', {})
    date_ranges = data.get('date_ranges', {})
    page = int(data.get('page', 1))
    page_size = int(data.get('page_size', 10))
    offset = (page - 1) * page_size

    where_clauses = []
    order_clauses = []
    params = []

    if not page or not page_size:
            return jsonify({'error': 'Missing page or page_size'}), 400

    for field, value in filters.items():
        if field in allowed_fields:
            if value is True:
                where_clauses.append(f"{allowed_fields[field]} IS NOT NULL")
            elif value is False:
                where_clauses.append(f"{allowed_fields[field]} IS NULL")
            elif isinstance(value, (str, int, float)):
                if field in fuzzy_fields:
                    where_clauses.append(f"{allowed_fields[field]} LIKE %s")
                    # params.append(f"%{value.replace('%', r'\%')}%")
                    params.append('%' + value.replace('%', r'\%') + '%')
                else:
                    where_clauses.append(f"{allowed_fields[field]} = %s")
                    params.append(value)

    for field, date_pair in date_ranges.items():
        if field in allowed_date_range_fields:
            start, end = normalize_date_range(date_pair)
            if start and end:
                where_clauses.append(f"{allowed_date_range_fields[field]} BETWEEN %s AND %s")
                params.extend([start, end])

    where_sql = " AND ".join(where_clauses)
    if where_sql:
        where_sql = "WHERE " + where_sql

    for field, value in order_fields.items():
        if field in allowed_fields:
            if value is True:
                order_clauses.append(f"{allowed_fields[field]}")
            else:
                order_clauses.append(f"{allowed_fields[field]} DESC")
        if field in allowed_date_range_fields:
            if value is True:
                order_clauses.append(f"{allowed_date_range_fields[field]}")
            else:
                order_clauses.append(f"{allowed_date_range_fields[field]} DESC")

    order_sql = ", ".join(order_clauses)
    if order_sql:
        order_sql = "ORDER BY " + order_sql

    params.extend([page_size, offset])

    return where_sql, order_sql, params, page, page_size

def execute_query_sql(count_sql, query_sql, params):
    conn = get_db_connection()
    cursor = conn.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute(query_sql, params)
    rows = cursor.fetchall()
    
    cursor.execute(count_sql, params[:-2])  # 不要 LIMIT 参数
    total = cursor.fetchone()

    cursor.close()
    conn.close()

    return total, rows

@app.route('/api/company/query', methods=['POST'])
def query_company_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'company_id': 'company_id',
            'company_name': 'company_name',
            'company_type': 'company_type',
            'company_abbreviation': 'company_abbreviation'
        }
        allowed_date_range_fields = {
            'add_time': 'add_time'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        SELECT company_id, company_name, company_type, company_abbreviation, add_time, edit_time, note
        FROM knit_company
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        FROM knit_company
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/machine/query', methods=['POST'])
def query_machine_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'machine_id': 'A.machine_id',
            'machine_name': 'A.machine_name',
            'order_no': 'B.order_no',
            'order_cloth_name': 'B.order_cloth_name',
            'order_cloth_color': 'B.order_cloth_color',
        }
        allowed_date_range_fields = {
            'add_time': 'A.add_time'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.machine_id, A.machine_name, A.add_time, A.edit_time, A.note,
        B.order_no, B.order_cloth_name, B.order_cloth_color
        from knit_machine A left join knit_order B on A.machine_order_id = B.order_id
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        from knit_machine A left join knit_order B on A.machine_order_id = B.order_id
        {where_sql}
        """
        
        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/order/query', methods=['POST'])
def query_order_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'order_id': 'A.order_id',
            'order_no': 'A.order_no',
            'order_cloth_name': 'A.order_cloth_name',
            'order_cloth_color': 'A.order_cloth_color',
            'company_name': 'B.company_name',
            'company_abbreviation': 'B.company_abbreviation'
        }
        allowed_date_range_fields = {
            'add_time': 'A.add_time'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.order_id, A.order_no, A.order_cloth_name, A.order_cloth_color, A.order_cloth_piece,
        A.order_cloth_weight, A.order_cloth_weight_price, A.order_cloth_add, A.add_time, A.edit_time, A.note, 
        A.order_custom_company_id, 
        B.company_name, B.company_abbreviation
        from knit_order A left join knit_company B on A.order_custom_company_id = B.company_id
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        from knit_order A left join knit_company B on A.order_custom_company_id = B.company_id
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500
    
@app.route('/api/cloth/query', methods=['POST'])
def query_cloth_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'cloth_id': 'A.cloth_id',
            'cloth_delivery_id': 'A.cloth_delivery_id',
            'order_no': 'B.order_no',
            'order_cloth_name': 'B.order_cloth_name',
            'order_cloth_color': 'B.order_cloth_color',
            'machine_name': 'C.machine_name',
            'delivery_no': 'D.delivery_no',
            'delivery_status': 'D.delivery_no',
            'add_user_name': 'E.user_name'
        }
        allowed_date_range_fields = {
            'add_time': 'A.add_time',
            'delivery_time': 'IF(D.delivery_no IS NULL, NULL, A.cloth_delivery_time)'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.cloth_id, A.cloth_origin_weight, A.cloth_weight_correct, A.add_time, A.edit_time, A.note, 
        B.order_no, B.order_cloth_name, B.order_cloth_color, B.order_cloth_add, 
        C.machine_name, 
        D.delivery_no,
        E.user_name AS add_user_name, 
        IF(D.delivery_no IS NULL, 0, 1) AS delivery_status,
        IF(D.delivery_no IS NULL, NULL, A.cloth_delivery_time) AS delivery_time,
        (A.cloth_origin_weight + COALESCE(B.order_cloth_add, 0) + COALESCE(A.cloth_weight_correct, 0)) AS cloth_calculate_weight, 
        A.cloth_order_id, A.cloth_machine_id, A.cloth_delivery_id, A.add_user_id
        from knit_cloth A
        left join knit_order B on A.cloth_order_id = B.order_id
        left join knit_machine C on A.cloth_machine_id = C.machine_id
        left join knit_delivery D on A.cloth_delivery_id = D.delivery_id
        left join sys_user E on A.add_user_id = E.user_id
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        select COUNT(*) as total,
        SUM(A.cloth_origin_weight + COALESCE(B.order_cloth_add, 0) + COALESCE(A.cloth_weight_correct, 0)) as sum_weight
        from knit_cloth A
        left join knit_order B on A.cloth_order_id = B.order_id
        left join knit_machine C on A.cloth_machine_id = C.machine_id
        left join knit_delivery D on A.cloth_delivery_id = D.delivery_id
        left join sys_user E on A.add_user_id = E.user_id
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "sum_weight": total['sum_weight'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500 
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500


@app.route('/api/delivery/query', methods=['POST'])
def query_delivery_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'delivery_id': 'A.delivery_id',
            'delivery_no': 'A.delivery_no',
            'company_name': 'B.company_name',
            'company_abbreviation': 'B.company_abbreviation'
        }
        allowed_date_range_fields = {
            'add_time': 'A.add_time'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.delivery_id, A.delivery_no, A.add_time, A.edit_time, A.note, 
        A.delivery_company_id, 
        B.company_name, B.company_abbreviation, 
        COALESCE(C.delivery_piece, 0) AS delivery_piece, COALESCE(C.delivery_weight, 0) AS delivery_weight
        from knit_delivery A 
        left join knit_company B on A.delivery_company_id = B.company_id
        left join (
        select AA.cloth_delivery_id, COUNT(AA.cloth_id) AS delivery_piece, 
        SUM(AA.cloth_origin_weight + COALESCE(AA.cloth_weight_correct, 0) + COALESCE(BB.order_cloth_add, 0)) AS delivery_weight
        from knit_cloth AA
        left join knit_order BB on AA.cloth_order_id = BB.order_id
        GROUP BY AA.cloth_delivery_id
        ) C on A.delivery_id = C.cloth_delivery_id
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        from knit_delivery A 
        left join knit_company B on A.delivery_company_id = B.company_id
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500     
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500  

@app.route('/api/user/query', methods=['POST'])
def query_user_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'user_id': 'user_id',
            'user_name': 'user_name',
            'real_name': 'real_name',
            'user_status': '(is_locked + 1) * (1 - is_admin)',
            'print_status': '(1 - print_allowed) * (1 - is_admin)',
        }
        allowed_date_range_fields = {
            'add_time': 'add_time'
        }

        where_sql, order_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        SELECT user_id, user_name, real_name, (is_locked + 1) * (1 - is_admin) AS user_status,
        (1 - print_allowed) * (1 - is_admin) AS print_status, add_time, edit_time, note
        FROM sys_user
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        FROM sys_user
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total['total'],
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500
    
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/machine/search', methods=['POST'])
def machine_search():
    try:
        data = request.get_json()
        size = data.get('size')
        keyword = data.get('keyword')

        if not size or not isinstance(keyword, str):
            return jsonify({'error': 'Missing size or keyword'}), 400

        query_sql = f"""
        select A.machine_id, A.machine_name, B.order_id, B.order_no
        from knit_machine A
        left join knit_order B on A.machine_order_id = B.order_id
        where machine_name like CONCAT('%%', %s, '%%')
        ORDER BY LOCATE(%s, machine_name), machine_last_input_time DESC, machine_name
        LIMIT %s
        """

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query_sql, [keyword, keyword, size])
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/order/search', methods=['POST'])
def order_search():
    try:
        data = request.get_json()
        size = data.get('size')
        keyword = data.get('keyword')

        if not size or not isinstance(keyword, str):
            return jsonify({'error': 'Missing size or keyword'}), 400

        query_sql = f"""
        select order_id, order_no
        from knit_order 
        where order_no like CONCAT('%%', %s, '%%')
        ORDER BY LOCATE(%s, order_no), order_no
        LIMIT %s
        """

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query_sql, [keyword, keyword, size])
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500
    
@app.route('/api/company/search', methods=['POST'])
def company_search():
    try:
        data = request.get_json()
        size = data.get('size')
        keyword = data.get('keyword')

        if not size or not isinstance(keyword, str):
            return jsonify({'error': 'Missing size or keyword'}), 400

        query_sql = f"""
        select company_id, company_abbreviation
        from knit_company 
        where company_abbreviation like CONCAT('%%', %s, '%%')
        ORDER BY LOCATE(%s, company_abbreviation), company_abbreviation
        LIMIT %s
        """

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query_sql, [keyword, keyword, size])
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500    

@app.route('/api/login-before', methods=['POST'])
def login_before():
    try:
        if jwt_auth_manager.generate_token_available():
            private_key, public_key_str = generate_keys()
            token, error = jwt_auth_manager.generate_token(private_key)
            if not token:
                return jsonify({'error': error}), 403
            
            return jsonify({
                'token': token,
                'public_key': public_key_str,
            }), 201
        else:
            return jsonify({'error': 'Auth max limit reached'}), 403
    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500   

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('user_name')
        password = data.get('user_password')
        auth_token = data.get('auth_token')

        if not username or not password or not auth_token:
            return jsonify({'error': 'Username and password and auth_token are required'}), 400

        valid, result = jwt_auth_manager.verify_token(auth_token)
        if not valid:
            return jsonify({'error': result}), 401

        password = decrypt_password(password, result)

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
        sql = "SELECT user_id, user_name, user_password, is_admin, is_locked FROM sys_user WHERE user_name = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and int.from_bytes(user['is_locked'], 'big') == 1 and int.from_bytes(user['is_admin'], 'big') == 0:
            jwt_login_manager.logout_user(user['user_id'])
            return jsonify({'error': 'User has been locked'}), 401
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
            # 密码匹配
            token, error = jwt_login_manager.generate_token(user['user_id'])
            if not token:
                return jsonify({'error': error}), 403
            
            return jsonify({
                'token': token,
                'expires_seconds': JWT_EXPIRE_SECONDS,
                'user_name': user['user_name'],
                'is_admin': (int.from_bytes(user['is_admin'], 'big') == 1)
            }), 201
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    if jwt_login_manager.logout_token(request.headers.get('Authorization')):
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        return jsonify({'error': 'User not logged in'}), 400

@app.route('/api/check-login', methods=['GET'])
def check_login():
    return jsonify({
        'logged_in': True,
        'user': {
            'user_id': request.user['user_id'],
            'username': request.user['user_name'],
        }
    })

@app.route('/api/refresh-token', methods=['POST'])
def refresh_token():
    new_token, err = jwt_login_manager.refresh_token(request.headers.get('Authorization'))
    if new_token:
        return jsonify({
            'token': new_token,
            'expires_seconds': JWT_EXPIRE_SECONDS,
            'user_name': request.user['user_name'],
            'is_admin': (int.from_bytes(request.user['is_admin'], 'big') == 1)
        }), 201
    else:
        return jsonify({'error': err}), 400

@app.route('/api/test-info', methods=['GET'])
def test_info():
    with printer_lock:
        return jsonify({
            'printer_connect': printer_connected,
            'login_store': jwt_login_manager.login_store,
            'login_user': jwt_login_manager.index_user,
            'auth_store': jwt_auth_manager.auth_store
        }), 200

if __name__ == '__main__':
    # from flask_cors import CORS
    # CORS(app)
    # CORS(app, origins=['http://localhost:5173', 'http://127.0.0.1:5173']) #本地测试时启用

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

    # app.run(host='0.0.0.0', port=5000, debug=True, threaded=True, ssl_context=("../cert/server_cert.pem", "../cert/server_key.pem"))
