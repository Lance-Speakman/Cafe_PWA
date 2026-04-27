from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Python library for working with SQLite databases
import os       # Helps build file paths that work on all systems
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)  # allow requests from your local front-end

app.secret_key = "testKey123"
API_KEY = "test321" #for demo purposes 
SECRET_KEY = hashlib.sha256(b"my_super_secret_key").digest()
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = False

def deterministic_iv(plaintext: str) -> bytes:
    """
    Creates a repeatable 16-byte IV from plaintext.
    Same plaintext -> same IV.
    """
    return hashlib.sha256(plaintext.encode()).digest()[:16]

def pad(data: bytes) -> bytes:
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length]) * padding_length

def unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt(plaintext: str) -> str:
    iv = deterministic_iv(plaintext)
    cipher = Cipher(
        algorithms.AES(SECRET_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext.encode())) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt(encoded_text: str) -> str:
    raw = base64.b64decode(encoded_text)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(
        algorithms.AES(SECRET_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext).decode()

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper

# Opens a connection to orders.db inside the backend folder.
def get_db_connection():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # backend folder
    db_path = os.path.join(BASE_DIR, "orders.db")          # database path
    conn = sqlite3.connect(db_path)     # open database connection
    conn.row_factory = sqlite3.Row      # return rows like dicts
    return conn

@app.route('/')
def home():
    return "✅ Flask server is running!"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()

    stored_email = encrypt(email)

    cur.execute("SELECT CustomerID, Email, Password FROM Customers WHERE Email = ?", (stored_email,))
    row = cur.fetchone()

    if row and check_password_hash(row[2], password):
        if email == "admin@email.com":
            session['admin'] = email
            conn.close()
            return jsonify({"message": "Login successful"}), 200
    
    conn.close()
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/admin-links")
def admin_links():
    if 'admin' not in session:
        return jsonify({"links": []}), 401

    return jsonify({
        "links": [
            {"name": "View Customers", "url": "http://127.0.0.1:5050/customers"},
            {"name": "View Menu", "url": "http://127.0.0.1:5050/menu"},
            {"name": "View Orders", "url": "http://127.0.0.1:5050/orders"},
            {"name": "Log Out", "url": "http://127.0.0.1:5050/logout"}
        ]
    })

# POST route to receive data from the front-end
@app.route('/feedback', methods=['POST'])
def feedback():
    key = request.headers.get("API-Key")

    if key != API_KEY:
        return jsonify({"error": "Unauthorized access"}), 403
    
    data = request.get_json(force=True)  # JSON from fetch()
    message = (data or {}).get('message', '').strip()
    if not message:
        return jsonify({"error": "No message provided."}), 400
    print(f"[SERVER] Feedback received: {message}")
    # (Objects/data structures): 'message' is data app works with
    return jsonify({"response": f"Thanks! You said: {message}"}), 201

# Test route to read customers from the database
@app.route('/API/customers')
def get_customers_api():
    key = request.headers.get("API-Key")

    if key != API_KEY:
        return jsonify({"error": "Unauthorized access"}), 403
    conn = get_db_connection()   # open database
    rows = conn.execute(
        'SELECT CustomerID, CustomerName, Email FROM Customers'
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])  # convert rows to JSON

@app.route('/customers')
def get_customers():
    if 'admin' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db_connection()   # open database
    rows = conn.execute(
        'SELECT CustomerID, CustomerName, Email FROM Customers'
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])  # convert rows to JSON

# GET route: return all menu items
@app.route('/menu', methods=['GET'])
def get_menu():    
    conn = get_db_connection()   # open database using the helper
    rows = conn.execute(
        'SELECT MenuItemID, ItemName, Category, Price FROM MenuItems'
    ).fetchall()
    conn.close()

    menu = [dict(row) for row in rows]

    return jsonify({"menu": menu})

# POST route: reuse ID or create new one
@app.route('/API/orders', methods=['POST'])
def create_order():
    key = request.headers.get("API-Key")

    if key != API_KEY:
        return jsonify({"error": "Unauthorized access"}), 403
    data = request.get_json()

    customer_name  = data.get('customerName', 'Guest')
    customer_email = data.get('customerEmail')
    pickup_time    = data.get('pickupTime')
    items          = data.get('items', [])
    
    encrypted_email = encrypt(customer_email.lower().strip())
    encrypted_name = encrypt(customer_name.lower().strip())    
    
    conn = get_db_connection()
    cur = conn.cursor()

    # Try to find an existing customer with this email
    cur.execute("SELECT CustomerID FROM Customers WHERE Email = ?", (encrypted_email,))
    row = cur.fetchone()

    if row:
        # Reuse existing customer
        customer_id = row["CustomerID"]
    else:
        # Insert new customer
        cur.execute(
            "INSERT INTO Customers (CustomerName, Email, Password) VALUES (?, ?, ?)",
            (encrypted_name, encrypted_email, "")
        )
        customer_id = cur.lastrowid

    # Create the order record
    cur.execute(
        "INSERT INTO Orders (CustomerID, OrderDate) VALUES (?, ?)",
        (customer_id, pickup_time)
    )
    order_id = cur.lastrowid

    # Insert each item into the OrderItems table
    for item in items:
        cur.execute(
            "INSERT INTO OrderItems (OrderID, MenuItemID, Qty) VALUES (?, ?, ?)",
            (order_id, item["MenuItemID"], item.get("qty", 1))
        )

    conn.commit()
    conn.close()

    return jsonify({
        "message": f"✅ Order received! Your order number is {order_id}."
    })

@app.route('/orders', methods=['GET'])
def view_orders():
    if 'admin' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT
            o.ORDERID,
            O.OrderDate,
            c.CustomerName,
            c.Email,
            m.ItemName,
            oi.Qty
        FROM Orders o
        JOIN Customers c ON o.CustomerID = c.CustomerID
        JOIN OrderItems oi ON o.OrderID = oi.OrderID
        JOIN MenuItems m ON oi.MenuItemID = m.MenuItemID
        ORDER BY o.OrderDate DESC
    ''').fetchall()
    conn.close()

    orders = {}
    for row in rows:
        oid = row['OrderID']
        if oid not in orders:
            orders[oid] = {
                'OrderID': oid,
                'OrderDate': row['OrderDate'],
                'CustomerName': decrypt(row['CustomerName']),
                'Email': decrypt(row['Email']),
                'Items': []
            }
        orders[oid]['Items'].append({
            'ItemName': row['ItemName'],
            'Qty': row['Qty']
        })     
    return jsonify(list(orders.values()))

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

if __name__ == '__main__':
    app.run(debug=True, port=5050)