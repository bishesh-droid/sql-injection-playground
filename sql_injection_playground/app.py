import os
import sqlite3
import time
from flask import Flask, render_template, request, redirect, url_for, flash, g
from werkzeug.security import check_password_hash
import re # Added for NameError fix

from sql_injection_playground.config import Config
from sql_injection_playground.database import get_db_connection, init_db

# --- Flask Application Initialization ---

app = Flask(__name__)
app.config.from_object(Config)

# --- Database Management ---

# Function to get a database connection for the current request
def get_db():
    if 'db' not in g:
        g.db = get_db_connection()
    return g.db

# Function to close the database connection after each request
@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- Routes ---

@app.route('/')
def index():
    """
    Home page displaying links to vulnerable and secure features.
    """
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page vulnerable to SQL Injection (Login Bypass).
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # --- VULNERABLE SQL QUERY ---
        # User input is directly concatenated into the SQL query without proper sanitization.
        # This allows for SQL Injection attacks like ' OR 1=1--
        query = f"SELECT * FROM users WHERE username = '{username}'"
        # In a real scenario, password would also be checked, but for SQLi demo, username is enough
        # and we'll check hashed password after fetching the user.

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()

            if user:
                # Check for common SQLi bypass payloads in username
                if "'--" in username or "' OR '1'='1" in username:
                    flash(f'Login successful as {user['username']} ({user['role']}) (SQLi Bypass)! ', 'success')
                    return redirect(url_for('index'))
                # If no bypass, proceed with normal password check
                elif check_password_hash(user['password'], password):
                    flash(f'Login successful as {user['username']} ({user['role']})!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid credentials.', 'danger')
            else:
                flash('Invalid credentials.', 'danger')
        except sqlite3.Error as e:
            # Error-based SQLi will often trigger this. Displaying the error is part of the vulnerability.
            flash(f'Database error: {e}', 'danger')
            app.logger.error(f"SQL Error in login: {e} for query: {query}")

    return render_template('login.html')

@app.route('/search', methods=['GET'])
def search():
    """
    Product search page vulnerable to Error-based and UNION-based SQL Injection.
    """
    query = request.args.get('query', '')
    products = []
    message = None

    if query:
        # --- VULNERABLE SQL QUERY ---
        # User input is directly concatenated into the SQL query.
        # Allows for UNION SELECT and error-based SQLi.
        sql_query = f"SELECT id, name, description, price, category FROM products WHERE id = {query}"

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(sql_query)
            products = cursor.fetchall()
            if not products and message is None:
                message = "No products found matching your query."
        except sqlite3.Error as e:
            print(f"DEBUG: Database error: {e}")
            message = f'Database error: {e}'
            app.logger.error(f"SQL Error in search: {e} for query: {sql_query}")

    return render_template('search.html', query=query, products=products, message=message)

@app.route('/product')
def product_details_vulnerable():
    """
    Product details page vulnerable to Boolean-based Blind and Time-based Blind SQL Injection.
    """
    product_id = request.args.get('id', '1') # Default to ID 1 if not provided
    product = None

    # --- VULNERABLE SQL QUERY ---
    # User input is directly concatenated into the SQL query.
    # This is vulnerable to blind SQLi where the attacker infers data based on response (or lack thereof).
    query = f"SELECT id, name, description, price, category FROM products WHERE id = {product_id}"

    # Simulate sqlite_sleep for time-based blind SQLi demonstration
    sleep_match = re.search(r'sqlite_sleep\((\d+)\)', product_id)
    if sleep_match:
        sleep_time = int(sleep_match.group(1))
        time.sleep(sleep_time)
        app.logger.info(f"Simulating sqlite_sleep for {sleep_time} seconds.")

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(query)
        product = cursor.fetchone()
    except sqlite3.Error as e:
        # In blind SQLi, errors might not be displayed, but for demonstration, we log them.
        app.logger.error(f"SQL Error in vulnerable product details: {e} for query: {query}")
        # For time-based blind, the delay itself is the indicator, not an error message.

    return render_template('product.html', product=product)

@app.route('/secure_product')
def product_details_secure():
    """
    Product details page using parameterized queries (secure against SQL Injection).
    """
    product_id = request.args.get('id', '1')
    product = None

    # --- SECURE SQL QUERY ---
    # Using parameterized queries (prepared statements) prevents SQL Injection.
    # The database driver handles proper escaping of user input.
    query = "SELECT id, name, description, price, category FROM products WHERE id = ?"

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(query, (product_id,))
        product = cursor.fetchone()
    except sqlite3.Error as e:
        app.logger.error(f"SQL Error in secure product details: {e}")
        flash('An error occurred while fetching product details.', 'danger')

    return render_template('secure_product.html', product=product)

# --- CLI for Database Initialization ---

@app.cli.command('init-db')
def init_db_command():
    """
    Initializes the database with schema and sample data.
    """
    init_db()
    print('Database initialized.')

# --- Main Execution Block ---

if __name__ == '__main__':
    # This block is for running the Flask app directly for development.
    # For production, use a WSGI server (e.g., Gunicorn).
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)
