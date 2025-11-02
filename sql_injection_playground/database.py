# sql_injection_playground/database.py

import sqlite3
import os
from werkzeug.security import generate_password_hash

# Import the database path from the configuration
from sql_injection_playground.config import Config

DATABASE_PATH = Config.DATABASE

def get_db_connection():
    """
    Establishes a connection to the SQLite database.

    Returns:
        sqlite3.Connection: A database connection object.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    # Configure row_factory to return rows as dictionary-like objects
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database by creating tables and inserting initial data.
    This function will create the database file if it doesn't exist.
    """
    # Check if the database file already exists. If so, remove it to start fresh.
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
        print(f"[INFO] Removed existing database: {DATABASE_PATH}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Create 'users' table for login functionality
    # This table will be vulnerable to SQLi login bypass
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
    """)
    print("[INFO] Created 'users' table.")

    # Create 'products' table for product search/details functionality
    # This table will be vulnerable to various SQLi types (error-based, union-based, blind)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT
        );
    """)
    print("[INFO] Created 'products' table.")

    # Insert initial data into 'users' table
    # Passwords are hashed for realism, though the vulnerability is in the query construction.
    hashed_admin_password = generate_password_hash("adminpass")
    hashed_user_password = generate_password_hash("userpass")
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", hashed_admin_password, "admin"))
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("user", hashed_user_password, "user"))
    print("[INFO] Inserted initial data into 'users' table.")

    # Insert initial data into 'products' table
    products_data = [
        ("Laptop Pro", "High-performance laptop for professionals.", 1200.00, "Electronics"),
        ("Mechanical Keyboard", "Tactile and clicky mechanical keyboard.", 150.00, "Accessories"),
        ("Gaming Mouse", "Ergonomic mouse for gaming.", 75.00, "Accessories"),
        ("Monitor 4K", "27-inch 4K UHD monitor.", 450.00, "Electronics"),
        ("Webcam HD", "Full HD webcam for video calls.", 60.00, "Peripherals"),
        ("USB Drive 128GB", "High-speed USB 3.0 flash drive.", 30.00, "Storage"),
        ("External SSD 1TB", "Portable SSD for fast data transfer.", 100.00, "Storage"),
    ]
    cursor.executemany("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)", products_data)
    print("[INFO] Inserted initial data into 'products' table.")

    conn.commit()
    conn.close()
    print(f"[INFO] Database initialized successfully at {DATABASE_PATH}")

if __name__ == "__main__":
    # This block allows running database initialization directly
    # python -m sql_injection_playground.database
    init_db()
