import os
import sqlite3
import secrets
import hashlib
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'farro_keys.db')
DOWNLOAD_DIR = os.path.join(BASE_DIR, 'downloads')
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('FARRO_SECRET_KEY', 'change-this-in-production')

ADMIN_USERNAME = os.environ.get('FARRO_ADMIN_USER', 'Farro-dev')
ADMIN_PASSWORD = os.environ.get('FARRO_ADMIN_PASS', 'Farro_dev@0&$-dev')
TELEGRAM_HANDLE = os.environ.get('FARRO_TELEGRAM_HANDLE', '@FarroITSupport')

PLANS = {
    'trial_20m': {'label': 'Trial 20 Minutes', 'minutes': 20, 'price': 'Free'},
    '5d': {'label': '5 Days', 'days': 5, 'price': 'Free / Manual'},
    '10d': {'label': '10 Days', 'days': 10, 'price': 'Free / Manual'},
    '15d': {'label': '15 Days', 'days': 15, 'price': 'Free / Manual'},
    '20d': {'label': '20 Days', 'days': 20, 'price': 'Free / Manual'},
    '30d': {'label': '30 Days', 'days': 30, 'price': 'Free / Manual'},
}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS license_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            plan_code TEXT NOT NULL,
            duration_minutes INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'unused',
            created_at TEXT NOT NULL,
            expires_at TEXT,
            activated_at TEXT,
            bound_device_id TEXT,
            last_seen_at TEXT,
            notes TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS app_downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def hash_device(device_id: str) -> str:
    return hashlib.sha256(device_id.encode('utf-8')).hexdigest()


def create_key(plan_code: str) -> str:
    token = secrets.token_hex(4).upper()
    prefix = plan_code.upper().replace('_', '')
    return f'FRR-{prefix}-{token}'


def duration_for_plan(plan_code: str) -> int:
    plan = PLANS[plan_code]
    if 'minutes' in plan:
        return int(plan['minutes'])
    return int(plan['days']) * 24 * 60


def Farro-dev_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('Farro-dev_logged_in'):
            return redirect(url_for('Farro-dev_login'))
        return f(*args, **kwargs)
    return wrapper


@app.route('/')
def index():
    conn = get_db()
    latest = conn.execute('SELECT file_name FROM app_downloads ORDER BY id DESC LIMIT 1').fetchone()
    counts = conn.execute("SELECT status, COUNT(*) AS c FROM license_keys GROUP BY status").fetchall()
    conn.close()
    count_map = {row['status']: row['c'] for row in counts}
    return render_template('index.html', plans=PLANS, latest=latest, counts=count_map, telegram_handle=TELEGRAM_HANDLE)


@app.route('/trial-key')
def trial_key():
    conn = get_db()
    row = conn.execute("SELECT license_key FROM license_keys WHERE plan_code='trial_20m' AND status='unused' ORDER BY id ASC LIMIT 1").fetchone()
    if row:
        key = row['license_key']
    else:
        key = create_key('trial_20m')
        conn.execute(
            'INSERT INTO license_keys (license_key, plan_code, duration_minutes, status, created_at) VALUES (?, ?, ?, ?, ?)',
            (key, 'trial_20m', duration_for_plan('trial_20m'), 'unused', datetime.utcnow().isoformat())
        )
        conn.commit()
    conn.close()
    return jsonify({'ok': True, 'key': key, 'plan': PLANS['trial_20m']['label']})


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)


@app.route('/api/activate', methods=['POST'])
def api_activate():
    data = request.get_json(force=True, silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    device_id = (data.get('device_id') or '').strip()
    if not license_key or not device_id:
        return jsonify({'ok': False, 'message': 'license_key and device_id are required'}), 400

    device_hash = hash_device(device_id)
    now = datetime.utcnow()
    conn = get_db()
    row = conn.execute('SELECT * FROM license_keys WHERE license_key = ?', (license_key,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'ok': False, 'message': 'Invalid key'}), 404

    expires_at = datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None
    if row['status'] == 'expired' or (expires_at and now > expires_at):
        conn.execute("UPDATE license_keys SET status='expired', last_seen_at=? WHERE id=?", (now.isoformat(), row['id']))
        conn.commit()
        conn.close()
        return jsonify({'ok': False, 'message': 'Key expired. Application should lock and request a new key.'}), 403

    if row['status'] == 'unused':
        expires = now + timedelta(minutes=row['duration_minutes'])
        conn.execute(
            "UPDATE license_keys SET status='active', activated_at=?, expires_at=?, bound_device_id=?, last_seen_at=? WHERE id=?",
            (now.isoformat(), expires.isoformat(), device_hash, now.isoformat(), row['id'])
        )
        conn.commit()
        conn.close()
        return jsonify({'ok': True, 'message': 'Activated', 'expires_at': expires.isoformat(), 'bound': True})

    if row['bound_device_id'] != device_hash:
        conn.close()
        return jsonify({'ok': False, 'message': 'Key already used on another device'}), 403

    conn.execute('UPDATE license_keys SET last_seen_at=? WHERE id=?', (now.isoformat(), row['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'message': 'Key valid', 'expires_at': row['expires_at'], 'bound': True})


@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json(force=True, silent=True) or {}
    license_key = (data.get('license_key') or '').strip()
    device_id = (data.get('device_id') or '').strip()
    if not license_key or not device_id:
        return jsonify({'ok': False, 'message': 'license_key and device_id are required'}), 400

    device_hash = hash_device(device_id)
    now = datetime.utcnow()
    conn = get_db()
    row = conn.execute('SELECT * FROM license_keys WHERE license_key=?', (license_key,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'ok': False, 'message': 'Invalid key'}), 404
    if row['bound_device_id'] != device_hash:
        conn.close()
        return jsonify({'ok': False, 'message': 'Device mismatch'}), 403
    expires_at = datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None
    if row['status'] == 'expired' or (expires_at and now > expires_at):
        conn.execute("UPDATE license_keys SET status='expired', last_seen_at=? WHERE id=?", (now.isoformat(), row['id']))
        conn.commit()
        conn.close()
        return jsonify({'ok': False, 'message': 'Expired'}), 403
    conn.execute('UPDATE license_keys SET last_seen_at=? WHERE id=?', (now.isoformat(), row['id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'message': 'Valid', 'expires_at': row['expires_at']})


@app.route('/Farro-dev/login', methods=['GET', 'POST'])
def Farro-dev_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['Farro-dev_logged_in'] = True
            return redirect(url_for('Farro-dev_panel'))
        flash('Wrong username or password.')
    return render_template('Farro-dev_login.html')


@app.route('/Farro-dev/logout')
def Farro-dev_logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/Farro-dev', methods=['GET', 'POST'])
@Farro-dev_required
def Farro-dev_panel():
    conn = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate':
            plan_code = request.form.get('plan_code')
            quantity = max(1, min(int(request.form.get('quantity', 1)), 1000))
            for _ in range(quantity):
                key = create_key(plan_code)
                conn.execute(
                    'INSERT INTO license_keys (license_key, plan_code, duration_minutes, status, created_at) VALUES (?, ?, ?, ?, ?)',
                    (key, plan_code, duration_for_plan(plan_code), 'unused', datetime.utcnow().isoformat())
                )
            conn.commit()
            flash(f'{quantity} keys generated.')
        elif action == 'expire':
            key_id = request.form.get('key_id')
            conn.execute("UPDATE license_keys SET status='expired' WHERE id=?", (key_id,))
            conn.commit()
            flash('Key marked expired.')
        elif action == 'reset':
            key_id = request.form.get('key_id')
            conn.execute("UPDATE license_keys SET status='unused', activated_at=NULL, expires_at=NULL, bound_device_id=NULL, last_seen_at=NULL WHERE id=?", (key_id,))
            conn.commit()
            flash('Key reset to unused.')
        elif action == 'register_download':
            file_name = request.form.get('file_name', '').strip()
            if file_name:
                conn.execute('INSERT INTO app_downloads (file_name, created_at) VALUES (?, ?)', (file_name, datetime.utcnow().isoformat()))
                conn.commit()
                flash('Download file name saved.')

    rows = conn.execute('SELECT * FROM license_keys ORDER BY id DESC LIMIT 300').fetchall()
    latest = conn.execute('SELECT file_name FROM app_downloads ORDER BY id DESC LIMIT 1').fetchone()
    counts = conn.execute("SELECT status, COUNT(*) AS c FROM license_keys GROUP BY status").fetchall()
    conn.close()
    count_map = {row['status']: row['c'] for row in counts}
    return render_template('Farro-dev.html', rows=rows, plans=PLANS, counts=count_map, latest=latest)


@app.route('/api/device-id-sample')
def device_id_sample():
    sample = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'sample-device'))
    return jsonify({'device_id_example': sample})


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
