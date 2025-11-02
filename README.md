# Python SQL Injection Playground

This project is an **intentionally vulnerable** web application built with Flask and SQLite, designed to serve as a safe and legal environment for learning, practicing, and understanding various types of SQL Injection (SQLi) attacks. It includes endpoints vulnerable to Error-based, UNION-based, Boolean-based Blind, and Time-based Blind SQLi, as well as a login bypass vulnerability. A secure endpoint is also provided for comparison.

> **WARNING:** This application is **intentionally insecure**. It is built for educational purposes ONLY. DO NOT use this code in production environments. Only run this application on your local machine or on a private, isolated network. **NEVER** deploy it to a public server, as it would be immediately compromised. The techniques demonstrated here are for learning how SQLi works, not for attacking real websites.

## Ethical Considerations

Understanding SQL Injection is crucial for developing secure web applications, but it comes with significant ethical responsibilities:

-   **Educational Use Only:** This playground is strictly for learning. Do not use the techniques learned here to attack any system you do not own or have explicit, written permission to test.
-   **Never Deploy Publicly:** This application is designed to be vulnerable. Deploying it to a public server would expose it to immediate compromise and potential misuse by malicious actors.
-   **What Not To Do:** The code in this project demonstrates common insecure coding practices that lead to SQLi. It serves as an example of **what not to do** in real-world application development.
-   **Responsible Disclosure:** If you discover a SQLi vulnerability in a real web application (with permission), report it responsibly to the owner and allow them time to fix it before any public disclosure.

## Features

-   **Flask Web Application:** A simple web interface built with Flask.
-   **SQLite Database:** A lightweight, file-based database for easy setup and reset.
-   **Vulnerable Login:** Demonstrates SQLi login bypass.
-   **Vulnerable Product Search:** Illustrates Error-based and UNION-based SQLi.
-   **Vulnerable Product Details:** Shows Boolean-based Blind and Time-based Blind SQLi.
-   **Secure Product Details:** An example of a properly parameterized query, demonstrating how to prevent SQLi.
-   **Database Initialization CLI:** A command-line interface to easily set up and reset the vulnerable database.
-   **Detailed Code Comments:** Extensive comments explain the vulnerable code segments and the underlying SQLi principles.

## Project Structure

```
.
├── sql_injection_playground/
│   ├── __init__.py
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   └── templates/
│       ├── index.html
│       ├── login.html
│       ├── product.html
│       ├── search.html
│       └── secure_product.html
├── tests/
│   ├── __init__.py
│   └── test_playground.py
├── .env.example
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Python-SQL-Injection-Playground.git
    cd Python-SQL-Injection-Playground
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    Copy the `.env.example` file to `.env` and update the `FLASK_SECRET_KEY` with a strong, random value (though for a playground, a simple one is fine).
    ```bash
    cp .env.example .env
    # Open .env and edit FLASK_SECRET_KEY if desired
    ```

## Usage

### 1. Initialize the Database

Before running the application, you need to initialize the SQLite database. This command will create `database.db` in the project root and populate it with sample users and products.

```bash
flask --app sql_injection_playground.app init-db
```

### 2. Run the Web Application

Start the Flask development server:

```bash
flask --app sql_injection_playground.app run
```

The application will be accessible at `http://127.0.0.1:5000/`.

### 3. Explore and Exploit Vulnerabilities

Navigate to `http://127.0.0.1:5000/` in your web browser to access the playground's home page, which provides links and hints for each vulnerable feature.

#### a. Login Bypass (Vulnerable Login Page: `/login`)

-   **Vulnerability:** The login form concatenates user input directly into the SQL query.
-   **Exploitation:**
    -   **Username:** `admin'--`
    -   **Password:** (anything)
    -   This payload makes the `WHERE` clause always true, bypassing authentication.

#### b. Error-based and UNION-based SQL Injection (Vulnerable Product Search: `/search`)

-   **Vulnerability:** The product search query directly incorporates user input.
-   **Exploitation:**
    -   **Error-based:** Enter `%' AND 1=CAST((SELECT name FROM sqlite_master LIMIT 1) AS INT)--` in the search box. This will cause a database error revealing table names.
    -   **UNION-based:** To dump user credentials, you need to match the number of columns. The `products` table has 5 columns (`id`, `name`, `description`, `price`, `category`). The `users` table has 4 (`id`, `username`, `password`, `role`). You can use `%' UNION SELECT NULL, username, password, NULL, NULL FROM users--` in the search box to retrieve usernames and hashed passwords.

#### c. Boolean-based Blind SQL Injection (Vulnerable Product Details: `/product?id=<ID>`)

-   **Vulnerability:** The product ID parameter is directly used in the query. The page response changes based on the truthiness of the injected condition.
-   **Exploitation:**
    -   **True condition:** `http://127.0.0.1:5000/product?id=1 AND 1=1` (Product 1 should be displayed).
    -   **False condition:** `http://127.0.0.1:5000/product?id=1 AND 1=2` (Product 1 should NOT be displayed, indicating the condition was false).
    -   You can use this to infer information character by character (e.g., `?id=1 AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a'`).

#### d. Time-based Blind SQL Injection (Vulnerable Product Details: `/product?id=<ID>`)

-   **Vulnerability:** Similar to boolean-based, but the response time indicates the truthiness of the injected condition.
-   **Exploitation:**
    -   **True condition (with delay):** `http://127.0.0.1:5000/product?id=1 AND (SELECT sqlite_sleep(5))` (Page will load after ~5 seconds).
    -   **False condition (no delay):** `http://127.0.0.1:5000/product?id=1 AND 1=2 AND (SELECT sqlite_sleep(5))` (Page will load quickly).
    -   This can be used to infer information when no other indicators are available.

#### e. Secure Product Details (`/secure_product?id=<ID>`)

-   This endpoint uses parameterized queries, which correctly separate SQL code from user input, making it immune to the SQL Injection techniques demonstrated above.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! If you have ideas for improvements or have found a bug, please open an issue or submit a pull request.

1.  **Fork the repository.**
2.  **Create a new branch:** `git checkout -b feature/your-feature-name`
3.  **Make your changes and commit them:** `git commit -m 'Add some feature'`
4.  **Push to the branch:** `git push origin feature/your-feature-name`
5.  **Open a pull request.**

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.