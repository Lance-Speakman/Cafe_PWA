import sqlite3, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "orders.db")

conn = sqlite3.connect(db_path)
conn.execute("INSERT INTO Customers (CustomerName, Email) VALUES (?, ?)",
             ('Jack Spratt', 'jack@example.com'))
conn.commit()
conn.close()

print("✅ Record inserted successfully!")