import mysql.connector  # Import the standard MySQL driver for Python
from flask import Flask, render_template, request, redirect, url_for, session, flash  # Import Flask components
import security_utils  # Import our custom security logic (hashing, validation)
import re  # Import Regular Expressions module for input validation (Defense against Malicious Links)
from db_config import DB_CONFIG

# Initialize the Flask application
app = Flask(__name__)

# Set a secret key for signing session cookies. 
# This protects against session tampering and ensures cryptographic integrity of the session data.
app.secret_key = 'super_secret_key_for_session_management'

def get_db_connection():
    """Establishes connection to the Remote MySQL database."""
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

# --- Helper Routes (Administrative/Utility) ---

@app.route('/reset_db')
def reset_db():
    """
    Resets the database to a clean state. 
    Useful for restarting the demonstration.
    """
    conn = get_db_connection()  # Open DB connection
    cursor = conn.cursor(dictionary=True)  # Create a cursor that returns rows as dictionaries
    
    # Execute raw SQL commands to clear tables. 
    # Note: These are hardcoded server-side commands, so they are safe from injection here.
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    
    # Reset the Auto Increment counters for ID columns
    cursor.execute("ALTER TABLE users AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE password_history AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE clients AUTO_INCREMENT = 1")
    
    conn.commit()  # Save changes
    conn.close()   # Close connection
    
    session.clear()  # Clear the user's session cookie
    flash('Database reset.', 'info')  # Show user feedback
    return redirect(url_for('register'))  # Redirect to registration

@app.route('/logout')
def logout():
    """
    Securely logs the user out.
    """
    session.clear()  # Wipes the session data from the server-side
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# --- SECURE CORE ROUTES (The Defense Implementation) ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles User Registration.
    SECURITY FIX: Uses Parameterized Queries to prevent SQL Injection.
    """
    if request.method == 'POST':
        # Retrieve form data from the request object
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Validate password complexity using our utility function
        # This prevents weak passwords (Part A requirement)
        is_valid, msg = security_utils.validate_password(password)
        if not is_valid:
            flash(msg, 'error')  # Show error if password is too weak
            return redirect(url_for('register'))

        # Securely hash the password using HMAC-SHA256 and a random Salt
        password_hash, salt = security_utils.hash_password(password)
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # !!! SECURITY DEFENSE: Parameterized Query !!!
        # We use '%s' as placeholders instead of directly injecting variables string.
        # This tells the MySQL driver to treat the inputs strictly as DATA, not executable SQL CODE.
        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)"
        
        try:
            # The data is passed as a second argument (tuple) to the execute function.
            # The driver handles the escaping and quoting automatically.
            cursor.execute(query, (username, email, password_hash, salt))
            conn.commit()  # Commit the transaction
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as e:
            flash(f'Error: {e}', 'error')  # Handle DB errors (e.g., duplicate username)
        finally:
            conn.close()  # Always close the connection

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles User Login.
    SECURITY FIX: Prevents UNION-Based SQL Injection (Imposter Attack).
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # !!! SECURITY DEFENSE: Parameterized Query !!!
            # Even if the attacker enters: ' UNION SELECT ...
            # The database will look for a user whose literal username is "' UNION SELECT ...".
            # It will NOT execute the UNION command.
            query = "SELECT * FROM users WHERE username = %s"
            
            cursor.execute(query, (username,))  # Pass username as a single-element tuple
            user = cursor.fetchone()  # Fetch the result
        
            if user:
                # Check if user is locked out
                if user['login_attempts'] >= 3:
                     flash('Account locked due to too many failed attempts. Contact support.', 'error')
                     return render_template('login.html')

                # Retrieve the Salt stored in the database for this user
                # Note: Since SQLi is blocked, this is guaranteed to be the REAL salt.
                # Calculate the hash of the input password using the retrieved salt
                check_hash, _ = security_utils.hash_password(password, user['salt'])
                
                # Compare the calculated hash with the stored hash
                # This relies on standard string comparison (secure enough for this context)
                if check_hash == user['password_hash']:
                    # Reset failed attempts counter on successful login
                    cursor.execute("UPDATE users SET login_attempts = 0 WHERE id = %s", (user['id'],))
                    conn.commit()
                    
                    # Login Success: Set session variables
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    return redirect(url_for('dashboard'))
                else:
                    # Increment failed attempts counter
                    cursor.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE id = %s", (user['id'],))
                    conn.commit()
                    flash('Invalid credentials', 'error')  # Generic error message (Good practice)
            else:
                flash('Invalid credentials', 'error')  # User not found

        except Exception as e:
             flash(f"SQL Error: {e}", "error")
             return render_template('login.html')
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """
    Main Dashboard.
    SECURITY FIX: 
    1. Prevents Stored XSS via Context-Aware Encoding (in Template).
    2. Prevents Malicious Links via Input Validation (Regex).
    """
    # Access Control: Check if user is logged in
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        client_name = request.form['client_name']
        description = request.form['description']
        website_url = request.form['website_url']

        # !!! SECURITY DEFENSE: Input Validation !!!
        # We verify that the URL protocol is strictly 'http' or 'https'.
        # This blocks vectors like 'javascript:alert(1)' which could execute code when clicked.
        if website_url and not re.match(r'^https?://', website_url):
             flash("Invalid URL! Must start with http:// or https://", "error")
        else:
            # Parameterized Query for Inserting Client Data
            # Prevents SQL Injection in the dashboard form
            query = "INSERT INTO clients (client_name, description, website_url) VALUES (%s, %s, %s)"
            cursor.execute(query, (client_name, description, website_url))
            conn.commit()
    
    # Fetch all clients to display
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()
    
    # Render the template. 
    # NOTE: In 'dashboard_secure.html', we do NOT use the '| safe' filter.
    # This means Jinja2 automatically converts characters like '<' to '&lt;', preventing XSS.
    return render_template('dashboard_secure.html', clients=clients)

@app.route('/search', methods=['GET'])
def search():
    """
    Search Functionality.
    SECURITY FIX: Prevents Reflected XSS via Auto-Escaping.
    """
    if 'user_id' not in session: return redirect(url_for('login'))
    
    # Get the search term from the URL query string
    query = request.args.get('q', '')
    
    # Pass the query to the template.
    # The template engine will automatically escape this string, neutralizing any script tags.
    return render_template('search_results_secure.html', query=query)

@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    """
    Deletes a client.
    SECURITY FIX: Uses Parameterized Queries for Deletion.
    """
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Parameterized Delete Statement
    # Prevents attackers from manipulating the WHERE clause
    cursor.execute("DELETE FROM clients WHERE id = %s", (client_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# --- Password Management Routes (Secured) ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the request for a password reset token.
    """
    if request.method == 'POST':
        # Generate a secure random token (SHA1)
        token = security_utils.generate_reset_token()
        
        # Simulation: Print token to server console instead of sending email
        print(f"!!! EMAIL SIMULATION !!! Reset Token: {token}")
        flash(f"Token sent to email (Check Server Console): {token}", "info")
        
        # Store token in session (In production, this should be in the DB with expiration)
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))
    return render_template('forgot_password.html')

@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    """
    Verifies that the user has the correct token.
    """
    if request.method == 'POST':
        user_token = request.form['token']
        # Compare submitted token with stored token
        if user_token == session.get('reset_token'):
            return redirect(url_for('change_password'))
        else:
            flash("Invalid Token", "error")
    return render_template('verify_token.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """
    Handles the actual password change process.
    Enforces policies: Complexity, History, and Correct Old Password.
    """
    if 'user_id' not in session: return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_pass = request.form['old_password']
        new_pass = request.form['new_password']
        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Secure Fetch: Get current user data using parameters
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        # Verify Old Password
        check_hash, _ = security_utils.hash_password(old_pass, user['salt'])
        if check_hash != user['password_hash']:
            flash("Old password incorrect", "error")
            conn.close()
            return redirect(url_for('change_password'))

        # Validate New Password Complexity
        is_valid, msg = security_utils.validate_password(new_pass)
        if not is_valid:
            flash(msg, "error")
            conn.close()
            return redirect(url_for('change_password'))

        # Calculate Hash for New Password
        new_hash, _ = security_utils.hash_password(new_pass, user['salt'])
        
        # Check Password History (Prevent reuse of last 3 passwords)
        # Using parameterized query for safety
        cursor.execute("SELECT password_hash FROM password_history WHERE user_id = %s ORDER BY timestamp DESC LIMIT 3", (user_id,))
        history = cursor.fetchall()
        
        for record in history:
            if record['password_hash'] == new_hash:
                flash("Cannot use last 3 passwords.", "error")
                conn.close()
                return redirect(url_for('change_password'))

        # Archive the OLD password hash into history
        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, user['password_hash']))
        
        # Update the user's password with the NEW hash
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
        
        conn.commit()
        conn.close()
        
        flash("Password changed successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

if __name__ == '__main__':
    # Run the app on port 5001 (Secure Port)
    # Debug mode is enabled for development
    app.run(debug=True, port=5001)