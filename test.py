import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import datetime
import MySQLdb

app = Flask(__name__)
CORS(app)
# CORS(app, expose_headers=["Authorization"])

# 建议放到配置中
JWT_SECRET = 'knit_secret_key'         # 用于生成token的密钥
JWT_EXPIRE_SECONDS = min(max(300, 300), 1800)         # token有效秒

# 配置 MySQL 连接
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '896784921'
app.config['MYSQL_DB'] = 'knittest'

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
    open_paths = ['/api/login']
    if request.path in open_paths:
        return  # 跳过校验
    if request.method == 'OPTIONS':
        return  # 预检请求直接放行
    # 校验 token
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Missing token'}), 401
    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        request.user = user_data
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT id, add_time, name FROM test_table where deleted=0 order by add_time")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify(rows)
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        name = data.get('name')

        if not name:
            return jsonify({'error': 'Missing name'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO test_table (name) VALUES (%s)", (name,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'User created'}), 201
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500


@app.route('/api/users', methods=['PUT'])
def update_user():
    try:
        data = request.get_json()
        user_id = data.get('id')
        name = data.get('name')

        if not user_id or not name:
            return jsonify({'error': 'Missing id or name'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # 执行更新语句
        cursor.execute("UPDATE test_table SET name = %s WHERE id = %s", (name, user_id))
        conn.commit()
        affected_rows = cursor.rowcount  # 检查是否有修改成功

        cursor.close()
        conn.close()

        if affected_rows == 0:
            return jsonify({'message': 'No user updated (invalid id?)'}), 404

        return jsonify({'message': 'User updated'}), 200
    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

    except Exception as e:
        return jsonify({'error': 'Unexpected error: ' + str(e)}), 500


@app.route('/api/users/delete', methods=['POST'])
def delete_users():
    try:
        data = request.get_json()
        ids = data.get('ids')

        if not ids or not isinstance(ids, list):
            return jsonify({'error': 'Invalid or missing "ids" list'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # 构造 SQL：DELETE FROM table WHERE id IN (%s, %s, ...)
        format_strings = ','.join(['%s'] * len(ids))
        sql = f"UPDATE test_table set deleted=1 WHERE id IN ({format_strings})"

        cursor.execute(sql, tuple(ids))
        conn.commit()
        affected_rows = cursor.rowcount

        cursor.close()
        conn.close()

        return jsonify({'message': f'Deleted {affected_rows} users'}), 200

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
        pk_values_json = json.dumps(pk_values)

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


def analyze_query_data(allowed_fields, data):
    filters = data.get('filters', {})
    date_range = data.get('date_range', {})
    page = int(data.get('page', 1))
    page_size = int(data.get('page_size', 10))
    offset = (page - 1) * page_size

    where_clauses = []
    params = []

    for field, value in filters.items():
        if field in allowed_fields:
            if isinstance(value, str) and '%' in value:
                where_clauses.append(f"{field} LIKE %s")
                params.append(value)
            else:
                where_clauses.append(f"{field} = %s")
                params.append(value)

    if 'beg_date' in date_range:
        where_clauses.append(f"add_time >= %s")
        params.append(date_range['beg_date'])

    if 'end_date' in date_range:
        where_clauses.append(f"add_time <= %s")
        params.append(date_range['end_date'])

    where_sql = " AND ".join(where_clauses)

    if where_sql:
        where_sql = "WHERE " + where_sql

    params.extend([page_size, offset])

    return where_sql, params, page, page_size

def execute_query_sql(count_sql, query_sql, params):
    conn = get_db_connection()
    cursor = conn.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute(count_sql, params[:-2])  # 不要 LIMIT 参数
    total = cursor.fetchone()['total']

    cursor.execute(query_sql, params)
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    return total, rows

@app.route('/api/company/query', methods=['POST'])
def query_company_with_pagination():
    try:
        data = request.get_json()

        allowed_fields = ['company_id', 'company_name', 'company_type', 'company_abbreviation']

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, data)

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
            "total": total,
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

        allowed_fields = ['machine_id', 'machine_name', 'order_no', 'order_cloth_name', 'order_cloth_color']

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, data)

        # 查询数据
        query_sql = f"""
        select * from (
        select A.machine_id, A.machine_name, A.add_time, A.edit_time, A.note,
        B.order_no, B.order_cloth_name, B.order_cloth_color
        from knit_machine A left join knit_order B on A.machine_order_id = B.order_id
        ) as tmp
        {where_sql}
        ORDER BY add_time DESC
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        from (
        select A.machine_id, A.machine_name, A.add_time, A.edit_time, A.note,
        B.order_no, B.order_cloth_name, B.order_cloth_color
        from knit_machine A left join knit_order B on A.machine_order_id = B.order_id
        ) as tmp
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total,
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

        allowed_fields = ['order_id', 'order_no', 'order_cloth_name', 'order_cloth_color', 'company_name', 'company_abbreviation']

        where_sql, params, page, page_size = analyze_query_data(allowed_fields, data)

        # 查询数据
        query_sql = f"""
        select * from (
        select A.order_id, A.order_no, A.order_cloth_name, A.order_cloth_color, A.order_cloth_piece,
        A.order_cloth_weight, A.order_cloth_weight_price, A.order_cloth_add, A.add_time, A.edit_time, A.note,
        B.company_name, B.company_abbreviation
        from knit_order A left join knit_company B on A.order_custom_company_id = B.company_id
        ) as tmp
        {where_sql}
        ORDER BY add_time DESC
        LIMIT %s OFFSET %s
        """

        # 查询总条数
        count_sql = f"""
        SELECT COUNT(*) as total
        from (
        select A.order_id, A.order_no, A.order_cloth_name, A.order_cloth_color, A.order_cloth_piece,
        A.order_cloth_weight, A.order_cloth_weight_price, A.order_cloth_add, A.add_time, A.edit_time, A.note,
        B.company_name, B.company_abbreviation
        from knit_order A left join knit_company B on A.order_custom_company_id = B.company_id
        ) as tmp
        {where_sql}
        """

        total, rows = execute_query_sql(count_sql, query_sql, params)

        return jsonify({
            "total": total,
            "page": page,
            "page_size": page_size,
            "records": rows
        }), 200

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('user_name')
        password = data.get('user_password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(MySQLdb.cursors.DictCursor)

        # 查询用户信息（包括加密后的密码）
        sql = "SELECT user_id, user_name, user_password FROM sys_user WHERE user_name = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
            # 密码匹配，生成 JWT
            exp_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=JWT_EXPIRE_SECONDS)
            payload = {
                'user_id': user['user_id'],
                'user_name': user['user_name'],
                'exp': exp_time
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'expires_at': int(exp_time.timestamp()),
                "expires_seconds": JWT_EXPIRE_SECONDS,
                'user_name': user['user_name'],
            }), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except MySQLdb.Error as e:
        return jsonify({'error': str(e)}), 500

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
    # 重新生成 token
    exp_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=JWT_EXPIRE_SECONDS)
    token = jwt.encode({
        'user_id': request.user['user_id'],
        'user_name': request.user['user_name'],
        'exp': exp_time
    }, JWT_SECRET, algorithm='HS256')

    return jsonify({
        'token': token,
        'expires_at': int(exp_time.timestamp()),
        "expires_seconds": JWT_EXPIRE_SECONDS,
        'user_name': request.user['user_name']
    })


if __name__ == '__main__':
    # print(bcrypt.hashpw('123456'.encode('utf-8'), bcrypt.gensalt()))
    app.run(debug=True)
#    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
