#!/usr/bin/env python3
"""
Project 09 – Enterprise Password Vault with Auto‑Rotation
Flask API + background rotation thread.
"""

import os
import sys
import time
import json
import yaml
import base64
import threading
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, render_template

# ---------- CONFIG ----------
CONFIG_FILE = "config.yaml"
with open(CONFIG_FILE, 'r') as f:
    config = yaml.safe_load(f)

# ---------- LOGGING ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config['vault'].get('log_file', 'vault.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------- ENCRYPTION ----------
KEY_FILE = config['vault']['key_file']
DATA_FILE = config['vault']['data_file']

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        logger.info("New encryption key generated.")
    return key

KEY = load_or_create_key()
cipher = Fernet(KEY)

def encrypt(data):
    return cipher.encrypt(json.dumps(data).encode())

def decrypt(encrypted):
    return json.loads(cipher.decrypt(encrypted).decode())

# ---------- DATA STORAGE ----------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'rb') as f:
            encrypted = f.read()
            try:
                return decrypt(encrypted)
            except:
                logger.error("Failed to decrypt data. Key may have changed.")
                return {}
    return {}

def save_data(data):
    encrypted = encrypt(data)
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted)
    logger.info("Data saved.")

# ---------- SECRET MANAGEMENT ----------
def add_secret(name, value, metadata=None):
    data = load_data()
    if name in data:
        return False, "Secret already exists."
    data[name] = {
        "value": value,
        "created": datetime.utcnow().isoformat(),
        "last_rotated": datetime.utcnow().isoformat(),
        "metadata": metadata or {},
        "rotation_count": 0
    }
    save_data(data)
    logger.info(f"Secret '{name}' added.")
    return True, "Secret added."

def get_secret(name):
    data = load_data()
    if name not in data:
        return None
    # Log access
    logger.info(f"Secret '{name}' accessed.")
    return data[name]

def list_secrets():
    data = load_data()
    return list(data.keys())

def delete_secret(name):
    data = load_data()
    if name not in data:
        return False, "Secret not found."
    del data[name]
    save_data(data)
    logger.info(f"Secret '{name}' deleted.")
    return True, "Secret deleted."

def rotate_secret(name):
    data = load_data()
    if name not in data:
        return False, "Secret not found."
    # Simulate rotation by generating a new random value
    import secrets
    new_value = secrets.token_urlsafe(24)
    data[name]["value"] = new_value
    data[name]["last_rotated"] = datetime.utcnow().isoformat()
    data[name]["rotation_count"] += 1
    save_data(data)
    logger.info(f"Secret '{name}' rotated.")
    return True, f"Secret rotated to {new_value}"

def rotate_all_secrets():
    data = load_data()
    count = 0
    for name in list(data.keys()):
        ok, _ = rotate_secret(name)
        if ok:
            count += 1
    logger.info(f"Rotated {count} secrets.")
    return count

# ---------- AUTO-ROTATION THREAD ----------
def auto_rotate_loop():
    rotation_days = config['vault'].get('rotation_days', 30)
    while True:
        try:
            data = load_data()
            now = datetime.utcnow()
            for name, info in data.items():
                last_rot = datetime.fromisoformat(info.get("last_rotated", "2000-01-01T00:00:00"))
                if (now - last_rot).days >= rotation_days:
                    logger.info(f"Auto-rotating '{name}' (last rotated {last_rot})")
                    rotate_secret(name)
        except Exception as e:
            logger.error(f"Auto-rotation error: {e}")
        time.sleep(3600)  # check every hour

# ---------- FLASK API ----------
app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('vault_dashboard.html')

@app.route('/api/secrets', methods=['GET'])
def api_list():
    secrets = list_secrets()
    return jsonify({"secrets": secrets})

@app.route('/api/secrets/<name>', methods=['GET'])
def api_get(name):
    secret = get_secret(name)
    if not secret:
        return jsonify({"error": "Not found"}), 404
    # Return without the actual value for security
    safe = {k: v for k, v in secret.items() if k != "value"}
    return jsonify(safe)

@app.route('/api/secrets/<name>/value', methods=['GET'])
def api_get_value(name):
    secret = get_secret(name)
    if not secret:
        return jsonify({"error": "Not found"}), 404
    # Requires an additional auth header in production
    return jsonify({"name": name, "value": secret["value"]})

@app.route('/api/secrets', methods=['POST'])
def api_add():
    data = request.json
    if not data or 'name' not in data or 'value' not in data:
        return jsonify({"error": "Missing name or value"}), 400
    ok, msg = add_secret(data['name'], data['value'], data.get('metadata'))
    if not ok:
        return jsonify({"error": msg}), 409
    return jsonify({"message": msg})

@app.route('/api/secrets/<name>/rotate', methods=['POST'])
def api_rotate(name):
    ok, msg = rotate_secret(name)
    if not ok:
        return jsonify({"error": msg}), 404
    return jsonify({"message": msg})

@app.route('/api/secrets/<name>', methods=['DELETE'])
def api_delete(name):
    ok, msg = delete_secret(name)
    if not ok:
        return jsonify({"error": msg}), 404
    return jsonify({"message": msg})

@app.route('/api/rotate_all', methods=['POST'])
def api_rotate_all():
    count = rotate_all_secrets()
    return jsonify({"rotated": count})

if __name__ == '__main__':
    # Start auto-rotation thread
    threading.Thread(target=auto_rotate_loop, daemon=True).start()
    logger.info("Vault server starting on port 5003...")
    app.run(host='0.0.0.0', port=config['vault'].get('port', 5003), debug=False)
