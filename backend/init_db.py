import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "orders.db")
schema_path = os.path.join(BASE_DIR, "schema.sql")

connection = sqlite3.connect(db_path)

with open(schema_path) as f:
    connection.executescript(f.read())

connection.commit()
connection.close()

print("✅ Database tables created successfully!")