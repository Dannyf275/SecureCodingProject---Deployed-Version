import mysql.connector
from db_config import DB_CONFIG # Import the config

def initialize_database():
    print("Connecting to MySQL Server...")
    
    # Connect directly to the specific database provided by the cloud host
    # Cloud providers usually create the DB for you, so we skip the "CREATE DATABASE" step
    # or we handle the connection safely.
    
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print(f"Connected to remote database: {DB_CONFIG['database']}")

        # --- Reset Tables ---
        cursor.execute("DROP TABLE IF EXISTS password_history")
        cursor.execute("DROP TABLE IF EXISTS clients")
        cursor.execute("DROP TABLE IF EXISTS users")

        # ... (Rest of the table creation code remains exactly the same) ...
        
        # --- Create Table: Users ---
        cursor.execute('''
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            salt VARCHAR(255) NOT NULL,
            login_attempts INT DEFAULT 0
        )
        ''')

        # ... (Keep the rest of your table definitions here) ...

        # --- Create Table: Password History ---
        cursor.execute('''
        CREATE TABLE password_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            password_hash VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')

        # --- Create Table: Clients ---
        cursor.execute('''
        CREATE TABLE clients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            client_name VARCHAR(255) NOT NULL,
            description TEXT,
            website_url TEXT
        )
        ''')

        conn.commit()
        conn.close()
        print("Remote MySQL Database initialized successfully.")

    except mysql.connector.Error as err:
        print(f"Error: {err}")

if __name__ == '__main__':
    initialize_database()