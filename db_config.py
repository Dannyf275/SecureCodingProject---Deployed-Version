import os

# REMOTE DATABASE CREDENTIALS
DB_CONFIG = {
    'host': 'gateway01.eu-central-1.prod.aws.tidbcloud.com', 
    'user': '2J2MJTDY1EBgZ3v.root',
    'password': 'RY6YN7y8PWN9H5oL',
    'database': 'test',
    'port': 4000, 
    'ssl_ca': '', # השאר ריק, הדרייבר ישתמש בברירת המחדל
    'use_pure': True # עוזר לעיתים בחיבורי ענן
    }