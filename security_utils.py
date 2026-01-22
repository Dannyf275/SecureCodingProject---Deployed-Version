import hashlib  # Library for hashing algorithms (SHA256)
import hmac     # Library for HMAC (Keyed-Hashing for Message Authentication)
import os       # Library for OS interactions (generating random bytes)
import re       # Library for Regular Expressions (Password validation)
import json     # Library to parse JSON configuration files

# Load security configuration from external file
CONFIG_FILE = 'config.json'

def load_config():
    """Reads security policies from config.json."""
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# Initialize config
config = load_config()
POLICY = config['password_policy']

def validate_password(password):
    """
    Checks if a password meets the complexity requirements.
    Returns: (bool, str) -> (IsValid, ErrorMessage)
    """
    # Check minimum length
    if len(password) < POLICY['min_length']:
        return False, f"Password must be at least {POLICY['min_length']} characters."

    # Check for uppercase letters
    if POLICY['require_uppercase'] and not any(char.isupper() for char in password):
        return False, "Password must contain an uppercase letter."

    # Check for lowercase letters
    if POLICY['require_lowercase'] and not any(char.islower() for char in password):
        return False, "Password must contain a lowercase letter."

    # Check for numbers
    if POLICY['require_numbers'] and not any(char.isdigit() for char in password):
        return False, "Password must contain a number."

    # Check for special characters using a predefined set
    specials = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    if POLICY['require_special_chars'] and not any(char in specials for char in password):
        return False, "Password must contain a special character."

    # Check against dictionary blocklist (Case-insensitive)
    for forbidden_word in POLICY.get('dictionary_blocklist', []):
        if forbidden_word.lower() in password.lower():
            return False, f"Password cannot contain commonly used words (e.g., '{forbidden_word}')."

    return True, "Valid"

def hash_password(password, salt=None):
    """
    Creates a secure HMAC-SHA256 hash.
    If salt is not provided, generates a new random salt.
    """
    if salt is None:
        # Generate 16 random bytes and convert to hex string
        salt = os.urandom(16).hex()
    
    # Create HMAC object using the salt as the key and SHA256 as the algorithm
    h = hmac.new(
        key=salt.encode('utf-8'), 
        msg=password.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    
    # Return the hex digest of the hash and the salt used
    return h.hexdigest(), salt

def generate_reset_token():
    """Generates a random SHA-1 token for password resets."""
    # Get random bytes
    random_data = os.urandom(20)
    # Hash using SHA-1 (as per project requirements)
    token = hashlib.sha1(random_data).hexdigest()
    return token