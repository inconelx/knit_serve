import json
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import bcrypt
import datetime
import MySQLdb
import base64
from JWTManager import JWTLoginManager

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

load_dotenv()

app = Flask(__name__)
# CORS(app)
CORS(app, origins=['http://localhost:5173', 'http://192.168.0.102:5173'])

# JWT设置
JWT_SECRET = os.getenv('JWT_SECRET')    # 用于生成token的密钥
JWT_EXPIRE_SECONDS = min(max(300, int(os.getenv('JWT_EXPIRE_SECONDS', 300))), 1800)    # token有效秒

# 其他设置
MAX_LOGINS = min(max(1, int(os.getenv('MAX_LOGINS', 8))), 16)
MAX_PRE_USER = min(max(1, int(os.getenv('MAX_PRE_USER', 1))), 16)
EMPLOYEE_CLOTH_EXPIRE_SECONDS = min(max(300, int(os.getenv('EMPLOYEE_CLOTH_EXPIRE_SECONDS', 600))), 1800)    #超出秒数后员工不可修改提交数据

# 配置 MySQL 连接
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

PRIVATE_KEY = None
PUBLIC_KEY_STR = None

# 创建连接
def get_db_connection():
    return MySQLdb.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        passwd=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        charset='utf8mb4'
    )

jwt_manager = JWTLoginManager(JWT_SECRET, JWT_EXPIRE_SECONDS, MAX_LOGINS, MAX_PRE_USER)

@app.before_request
def check_login_token():
    # 排除登录接口和其他公开接口
    open_paths = {'/api/login', '/api/public_key'}
    employee_paths = {
        '/api/logout',
        '/api/check-login',
        '/api/refresh-token',
        '/api/combobox',
        '/api/employee/cloth/add',
        '/api/employee/cloth/query',
        '/api/employee/cloth/update'
    }
    if request.path in open_paths:
        return  # 跳过校验
    if request.method == 'OPTIONS':
        return  # 预检请求直接放行
    # 校验 token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401
    
    valid, result = jwt_manager.verify_token(token)
    if not valid:
        return jsonify({'error': result}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
        sql = "SELECT user_id, user_name, is_admin, is_locked FROM sys_user WHERE user_id = %s"
        cursor.execute(sql, (result,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({'error': 'Missing user'}), 401
        
        if int.from_bytes(user['is_admin'], 'big') == 0:
            if int.from_bytes(user['is_locked'], 'big') == 1:
                jwt_manager.logout_user(result)
                return jsonify({'error': 'User has been locked'}), 401
            if request.path not in employee_paths:
                return jsonify({'error': 'Insufficient permissions'}), 400

        request.user = user

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

def load_or_generate_keys():
    global PRIVATE_KEY, PUBLIC_KEY_STR
    PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PUBLIC_KEY_STR = PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

@app.route('/api/public_key', methods=['GET'])
def get_public_key():
    return jsonify({'public_key': PUBLIC_KEY_STR})

def decrypt_password(encrypted_b64: str) -> str:
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted_bytes = PRIVATE_KEY.decrypt(
        encrypted_bytes,
        padding=padding.PKCS1v15())
    return decrypted_bytes.decode('utf-8')

@app.route('/api/user/add', methods=['POST'])
def user_add():
    try:
        data = request.get_json()
        json_data = data.get('json_data')

        if not json_data:
            return jsonify({'error': 'Missing json_data'}), 400

        json_data['user_password'] = decrypt_password(json_data['user_password_encrypted'])
        json_data.pop('user_password_encrypted', None)

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('insert_generic', ['sys_user', 'user_id', request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/user/update', methods=['POST'])
def user_update():
    try:
        data = request.get_json()
        pk_value = data.get('pk_value')
        json_data = data.get('json_data')

        if not json_data:
            return jsonify({'error': 'Missing json_data or pk_value'}), 400

        json_data['user_password'] = decrypt_password(json_data['user_password_encrypted'])
        json_data.pop('user_password_encrypted', None)

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('update_generic', ['sys_user', 'user_id', pk_value, request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

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

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

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
        left join sys_user E on E.user_id = %s and A.add_user_id = E.user_id
        {where_sql}
        ORDER BY add_time DESC, cloth_id DESC
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

@app.route('/api/employee/cloth/add', methods=['POST'])
def employee_cloth_add():
    try:
        data = request.get_json()
        json_data = data.get('json_data')

        if not json_data:
            return jsonify({'error': 'Missing json_data'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('insert_generic', ['knit_cloth', 'cloth_id', request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

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

        if not json_data:
            return jsonify({'error': 'Missing json_data or pk_value'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
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

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('update_generic', ['knit_cloth', 'cloth_id', pk_value, request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500    

@app.route('/api/generic/insert', methods=['POST'])
def insert_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        pk_name = data.get('pk_name')
        json_data = data.get('json_data')  # 这里假设客户端传的是一个 dict

        if not table_name or not pk_name or not json_data:
            return jsonify({'error': 'Missing required parameters'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('insert_generic', [table_name, pk_name, request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Insert successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500


@app.route('/api/generic/update', methods=['POST'])
def update_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        pk_name = data.get('pk_name')
        pk_value = data.get('pk_value')
        json_data = data.get('json_data')  # 这里假设客户端传的是一个 dict

        if not all([table_name, pk_name, json_data, pk_value]):
            return jsonify({'error': 'Missing required parameters'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('update_generic', [table_name, pk_name, pk_value, request.user['user_id'], json_str])
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({'message': 'Update successful'}), 201

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500
    
@app.route('/api/generic/update_batch', methods=['POST'])
def update_batch_generic():
    try:
        data = request.get_json()
        table_name = data.get('table_name')
        pk_name = data.get('pk_name')
        pk_values = data.get('pk_values')
        json_data = data.get('json_data')  # 这里假设客户端传的是一个 dict

        if not all([table_name, pk_name, json_data, pk_values]):
            return jsonify({'error': 'Missing required parameters'}), 400

        json_str = json.dumps(json_data, ensure_ascii=False)
        pk_values_json = json.dumps(pk_values, ensure_ascii=False)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.callproc('update_generic_batch', [table_name, pk_name, pk_values_json, request.user['user_id'], json_str])
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
        pk_name = data.get('pk_name')
        pk_values = data.get('pk_values')  # 期望是列表或数组

        if not all([table_name, pk_name, pk_values]):
            return jsonify({'error': 'Missing required parameters'}), 400

        pk_values_json = json.dumps(pk_values)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 调用存储过程
        cursor.callproc('delete_generic', (table_name, pk_name, request.user['user_id'], pk_values_json))
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
    date_ranges = data.get('date_ranges', {})
    page = int(data.get('page', 1))
    page_size = int(data.get('page_size', 10))
    offset = (page - 1) * page_size

    where_clauses = []
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
                    params.append(f"%{value.replace('%', r'\%')}%")
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

    params.extend([page_size, offset])

    return where_sql, params, page, page_size

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

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        SELECT company_id, company_name, company_type, company_abbreviation, add_time, edit_time, note
        FROM knit_company
        {where_sql}
        ORDER BY add_time DESC
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

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.machine_id, A.machine_name, A.add_time, A.edit_time, A.note,
        B.order_no, B.order_cloth_name, B.order_cloth_color
        from knit_machine A left join knit_order B on A.machine_order_id = B.order_id
        {where_sql}
        ORDER BY add_time DESC
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

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.order_id, A.order_no, A.order_cloth_name, A.order_cloth_color, A.order_cloth_piece,
        A.order_cloth_weight, A.order_cloth_weight_price, A.order_cloth_add, A.add_time, A.edit_time, A.note, 
        A.order_custom_company_id, 
        B.company_name, B.company_abbreviation
        from knit_order A left join knit_company B on A.order_custom_company_id = B.company_id
        {where_sql}
        ORDER BY add_time DESC
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
            'delivery_time': 'D.add_time'
        }

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        select A.cloth_id, A.cloth_origin_weight, A.cloth_weight_correct, A.add_time, A.edit_time, A.note, 
        B.order_no, B.order_cloth_name, B.order_cloth_color, B.order_cloth_add, 
        C.machine_name, 
        D.delivery_no, D.add_time AS delivery_time, 
        E.user_name AS add_user_name, 
        IF(D.delivery_no IS NULL, 0, 1) AS delivery_status,
        (A.cloth_origin_weight + COALESCE(B.order_cloth_add, 0) + COALESCE(A.cloth_weight_correct, 0)) AS cloth_calculate_weight, 
        A.cloth_order_id, A.cloth_machine_id, A.cloth_delivery_id, A.add_user_id
        from knit_cloth A
        left join knit_order B on A.cloth_order_id = B.order_id
        left join knit_machine C on A.cloth_machine_id = C.machine_id
        left join knit_delivery D on A.cloth_delivery_id = D.delivery_id
        left join sys_user E on A.add_user_id = E.user_id
        {where_sql}
        ORDER BY add_time DESC, cloth_id DESC
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        select COUNT(*) as total
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
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500 


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

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

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
        ORDER BY add_time DESC
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

@app.route('/api/user/query', methods=['POST'])
def query_user_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = {
            'user_id': 'user_id',
            'user_name': 'user_name',
            'real_name': 'real_name',
            'user_status': '(is_locked + 1) * (1 - is_admin)',
        }
        allowed_date_range_fields = {
            'add_time': 'add_time'
        }

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, allowed_date_range_fields, data)

        # 查询数据
        query_sql = f"""
        SELECT user_id, user_name, real_name, (is_locked + 1) * (1 - is_admin) AS user_status, add_time, edit_time, note
        FROM sys_user
        {where_sql}
        ORDER BY add_time DESC
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
        ORDER BY LOCATE(%s, machine_name), machine_name
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

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('user_name')
        password = decrypt_password(data.get('user_password_encrypted'))

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
        sql = "SELECT user_id, user_name, user_password, is_admin, is_locked FROM sys_user WHERE user_name = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and int.from_bytes(user['is_locked'], 'big') == 1 and int.from_bytes(user['is_admin'], 'big') == 0:
            jwt_manager.logout_user(user['user_id'])
            return jsonify({'error': 'User has been locked'}), 401
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
            # 密码匹配
            token, error = jwt_manager.generate_token(user['user_id'])
            if not token:
                return jsonify({'error': error}), 403
            
            return jsonify({
                'token': token,
                'expires_at': int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + JWT_EXPIRE_SECONDS,
                'expires_seconds': JWT_EXPIRE_SECONDS,
                'user_name': user['user_name'],
            }), 201
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    if jwt_manager.logout_token(request.headers.get('Authorization')):
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
    new_token, err = jwt_manager.refresh_token(request.headers.get('Authorization'))
    if new_token:
        return jsonify({
            'token': new_token,
            'expires_at': int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + JWT_EXPIRE_SECONDS,
            'expires_seconds': JWT_EXPIRE_SECONDS,
            'user_name': request.user['user_name'],
        }), 201
    else:
        return jsonify({'error': err}), 400

if __name__ == '__main__':
    # print(bcrypt.hashpw(''.encode('utf-8'), bcrypt.gensalt()))
    load_or_generate_keys()
    app.run(host='0.0.0.0', port=5000, debug=True)
    # app.run(host='0.0.0.0', port=5000, ssl_context='adhoc', debug=True)
