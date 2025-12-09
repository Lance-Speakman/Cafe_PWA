from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3  # Python library for working with SQLite databases
import os       # Helps build file paths that work on all systems

app = Flask(__name__)
CORS(app)  # allow requests from your local front-end

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


# POST route to receive data from the front-end
@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.get_json(force=True)  # JSON from fetch()
    message = (data or {}).get('message', '').strip()
    if not message:
        return jsonify({"error": "No message provided."}), 400
    print(f"[SERVER] Feedback received: {message}")
    # (Objects/data structures): 'message' is data app works with
    return jsonify({"response": f"Thanks! You said: {message}"}), 201

# Test route to read customers from the database
@app.route('/customers')
def get_customers():
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
@app.route('/orders', methods=['POST'])
def create_order():
    data = request.get_json()

    customer_name  = data.get('customerName', 'Guest')
    customer_email = data.get('customerEmail')
    pickup_time    = data.get('pickupTime')
    items          = data.get('items', [])

    conn = get_db_connection()
    cur = conn.cursor()

    # Try to find an existing customer with this email
    cur.execute("SELECT CustomerID FROM Customers WHERE Email = ?", (customer_email,))
    row = cur.fetchone()

    if row:
        # Reuse existing customer
        customer_id = row["CustomerID"]
    else:
        # Insert new customer
        cur.execute(
            "INSERT INTO Customers (CustomerName, Email) VALUES (?, ?)",
            (customer_name, customer_email)
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

if __name__ == '__main__':
    app.run(debug=True, port=5050)