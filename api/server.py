#!/usr/bin/env python3
"""
ZORV API Server - Sistema de Licenciamento
Backend completo com Flask para gerenciamento de keys
Compatível com deploy no Render (cloud) e local
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import os
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURAÇÃO
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)

# Detectar ambiente (Render define RENDER=true automaticamente)
IS_RENDER = os.getenv("RENDER", "").lower() in ("true", "1", "yes")
PORT = int(os.getenv("PORT", 5000))

# Banco de dados - Render usa /opt/render/project/src para persistência
if IS_RENDER:
    DB_DIR = Path("/opt/render/project/src/data")
else:
    DB_DIR = Path.home() / ".zorv_system"

DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "zorv.db"

# Chave secreta para admin API (configurar via variável de ambiente no Render)
ADMIN_SECRET = os.getenv("ZORV_ADMIN_SECRET", "zorv-admin-secret-key-2024")

# Senha admin padrão (configurar via variável de ambiente)
ADMIN_PASSWORD = os.getenv("ZORV_ADMIN_PASSWORD", "admin123")

# ─────────────────────────────────────────────────────────────────────────────
# BANCO DE DADOS
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    """Retorna conexão com o banco"""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    """Inicializa banco de dados"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS license_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT NOT NULL UNIQUE,
            key_formatted TEXT NOT NULL,
            customer_name TEXT DEFAULT '',
            customer_email TEXT DEFAULT '',
            days INTEGER DEFAULT -1,
            hwid TEXT DEFAULT '',
            activated BOOLEAN DEFAULT 0,
            activated_at TIMESTAMP,
            expires_at TIMESTAMP,
            revoked BOOLEAN DEFAULT 0,
            revoked_at TIMESTAMP,
            created_by TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_check TIMESTAMP,
            notes TEXT DEFAULT ''
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_code TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            hwid TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Criar admin padrão se não existir
    cursor.execute('SELECT COUNT(*) FROM admin_users')
    if cursor.fetchone()[0] == 0:
        pwd_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
        cursor.execute(
            'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
            ('admin', pwd_hash)
        )

    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# GERAÇÃO DE KEYS
# ─────────────────────────────────────────────────────────────────────────────

def calculate_checksum(payload):
    """Calcula checksum compatível com o sistema original"""
    hash_val = 0
    for char in payload:
        hash_val = ((hash_val << 5) - hash_val) + ord(char)
        hash_val = hash_val & 0xFFFFFFFF
    return str(abs(hash_val % 10))

def generate_key():
    """Gera uma key de 16 dígitos com checksum"""
    payload15 = ''.join([str(secrets.randbelow(10)) for _ in range(15)])
    checksum = calculate_checksum(payload15)
    key_code = payload15 + checksum
    return key_code

def format_key(key_code):
    """Formata key com hífens: XXXX-XXXX-XXXX-XXXX"""
    return f"{key_code[0:4]}-{key_code[4:8]}-{key_code[8:12]}-{key_code[12:16]}"

def validate_key_checksum(key):
    """Valida checksum de uma key"""
    digits = ''.join(c for c in key if c.isdigit())
    if len(digits) != 16:
        return False
    payload15 = digits[:15]
    checksum = digits[15]
    return checksum == calculate_checksum(payload15)

# ─────────────────────────────────────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

def require_admin(f):
    """Decorator para rotas admin"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if auth != f'Bearer {ADMIN_SECRET}':
            token = request.headers.get('X-Admin-Token', '')
            if token != ADMIN_SECRET:
                return jsonify({"error": "Unauthorized", "success": False}), 401
        return f(*args, **kwargs)
    return decorated

def log_action(key_code, action, details=""):
    """Registra ação no log"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        ip = request.remote_addr if request else "system"
        hwid = request.headers.get('X-HWID', '')
        cursor.execute(
            'INSERT INTO usage_logs (key_code, action, ip_address, hwid, details) VALUES (?, ?, ?, ?, ?)',
            (key_code, action, ip, hwid, details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# ROTAS PÚBLICAS (usadas pelo app desktop)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        "service": "ZORV License Server",
        "version": "2.0.0",
        "status": "online",
        "docs": "/api/health"
    })

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "online",
        "service": "ZORV License Server",
        "version": "2.0.0",
        "environment": "render" if IS_RENDER else "local",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/validate', methods=['POST'])
def validate_key():
    """Valida uma key e retorna informações da licença"""
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({"success": False, "error": "Key não fornecida"}), 400

    key_input = data['key'].strip()
    username = data.get('username', '')
    hwid = data.get('hwid', '')

    digits = ''.join(c for c in key_input if c.isdigit())

    if len(digits) != 16:
        return jsonify({"success": False, "error": "Formato inválido (16 dígitos)"}), 400

    if not validate_key_checksum(digits):
        return jsonify({"success": False, "error": "Checksum inválido"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM license_keys WHERE key_code = ?', (digits,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        log_action(digits, "validate_failed", "Key não encontrada no banco")
        return jsonify({"success": False, "error": "Key não encontrada"}), 404

    if row['revoked']:
        conn.close()
        log_action(digits, "validate_failed", "Key revogada")
        return jsonify({"success": False, "error": "Key revogada"}), 403

    days_remaining = -1
    if row['days'] != -1:
        if row['activated'] and row['expires_at']:
            expires_at = datetime.fromisoformat(row['expires_at'])
            now = datetime.now()
            if now > expires_at:
                conn.close()
                log_action(digits, "validate_failed", "Key expirada")
                return jsonify({"success": False, "error": "Key expirada"}), 403
            days_remaining = (expires_at - now).days
        else:
            days_remaining = row['days']

    if row['activated'] and row['hwid'] and hwid and row['hwid'] != hwid:
        conn.close()
        log_action(digits, "validate_failed", f"HWID mismatch: {hwid}")
        return jsonify({"success": False, "error": "Key já ativada em outro dispositivo"}), 403

    if not row['activated']:
        now = datetime.now()
        expires_at = None
        if row['days'] != -1:
            expires_at = (now + timedelta(days=row['days'])).isoformat()
            days_remaining = row['days']

        cursor.execute('''
            UPDATE license_keys
            SET activated = 1, activated_at = ?, expires_at = ?, hwid = ?, last_check = ?
            WHERE key_code = ?
        ''', (now.isoformat(), expires_at, hwid, now.isoformat(), digits))
    else:
        cursor.execute(
            'UPDATE license_keys SET last_check = ? WHERE key_code = ?',
            (datetime.now().isoformat(), digits)
        )

    conn.commit()
    conn.close()

    log_action(digits, "validate_success", f"User: {username}")

    return jsonify({
        "success": True,
        "message": "Key válida",
        "data": {
            "key": format_key(digits),
            "customer": row['customer_name'] or username,
            "days_remaining": days_remaining,
            "is_lifetime": row['days'] == -1,
            "activated_at": row['activated_at'] or datetime.now().isoformat(),
            "expires_at": row['expires_at'] if row['days'] != -1 else None
        }
    })

@app.route('/api/check', methods=['POST'])
def check_key():
    """Verifica se uma key ainda é válida (heartbeat)"""
    data = request.get_json()
    if not data or 'key' not in data:
        return jsonify({"success": False, "error": "Key não fornecida"}), 400

    digits = ''.join(c for c in data['key'] if c.isdigit())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM license_keys WHERE key_code = ?', (digits,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "valid": False}), 404

    if row['revoked']:
        conn.close()
        return jsonify({"success": True, "valid": False, "reason": "revoked"})

    if row['days'] != -1 and row['expires_at']:
        expires_at = datetime.fromisoformat(row['expires_at'])
        if datetime.now() > expires_at:
            conn.close()
            return jsonify({"success": True, "valid": False, "reason": "expired"})
        days_remaining = (expires_at - datetime.now()).days
    else:
        days_remaining = -1

    cursor.execute(
        'UPDATE license_keys SET last_check = ? WHERE key_code = ?',
        (datetime.now().isoformat(), digits)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "valid": True,
        "days_remaining": days_remaining,
        "is_lifetime": row['days'] == -1
    })

# ─────────────────────────────────────────────────────────────────────────────
# ROTAS ADMIN
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Login admin"""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Dados não fornecidos"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db()
    cursor = conn.cursor()
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute(
        'SELECT * FROM admin_users WHERE username = ? AND password_hash = ?',
        (username, pwd_hash)
    )
    user = cursor.fetchone()

    if user:
        conn.close()
        return jsonify({
            "success": True,
            "token": ADMIN_SECRET,
            "username": username
        })

    # Fallback: se a senha da variável de ambiente mudou, aceitar e atualizar o banco
    if username == 'admin' and password == ADMIN_PASSWORD:
        new_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
        cursor.execute(
            'UPDATE admin_users SET password_hash = ? WHERE username = ?',
            (new_hash, 'admin')
        )
        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "token": ADMIN_SECRET,
            "username": username
        })

    conn.close()
    return jsonify({"success": False, "error": "Credenciais inválidas"}), 401

@app.route('/api/admin/keys', methods=['GET'])
@require_admin
def list_keys():
    """Lista todas as keys"""
    conn = get_db()
    cursor = conn.cursor()

    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    limit = int(request.args.get('limit', 100))

    query = 'SELECT * FROM license_keys'
    params = []
    conditions = []

    if search:
        conditions.append('(key_code LIKE ? OR key_formatted LIKE ? OR customer_name LIKE ?)')
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if status == 'active':
        conditions.append('revoked = 0')
    elif status == 'revoked':
        conditions.append('revoked = 1')
    elif status == 'expired':
        conditions.append("days != -1 AND expires_at IS NOT NULL AND expires_at < datetime('now')")

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)

    query += ' ORDER BY created_at DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    keys = []
    for row in rows:
        days_remaining = -1
        is_expired = False
        if row['days'] != -1 and row['expires_at']:
            expires_at = datetime.fromisoformat(row['expires_at'])
            days_remaining = max(0, (expires_at - datetime.now()).days)
            is_expired = datetime.now() > expires_at

        keys.append({
            "id": row['id'],
            "key_code": row['key_code'],
            "key_formatted": row['key_formatted'],
            "customer_name": row['customer_name'],
            "customer_email": row['customer_email'],
            "days": row['days'],
            "days_remaining": days_remaining,
            "is_lifetime": row['days'] == -1,
            "is_expired": is_expired,
            "activated": bool(row['activated']),
            "activated_at": row['activated_at'],
            "expires_at": row['expires_at'],
            "revoked": bool(row['revoked']),
            "revoked_at": row['revoked_at'],
            "hwid": row['hwid'],
            "created_by": row['created_by'],
            "created_at": row['created_at'],
            "last_check": row['last_check'],
            "notes": row['notes']
        })

    return jsonify({"success": True, "keys": keys, "total": len(keys)})

@app.route('/api/admin/keys/generate', methods=['POST'])
@require_admin
def generate_new_key():
    """Gera uma nova key"""
    data = request.get_json() or {}

    customer_name = data.get('customer_name', '')
    customer_email = data.get('customer_email', '')
    days = data.get('days', -1)
    notes = data.get('notes', '')
    created_by = data.get('created_by', 'admin')
    quantity = min(data.get('quantity', 1), 100)

    generated_keys = []

    conn = get_db()
    cursor = conn.cursor()

    for _ in range(quantity):
        key_code = generate_key()
        key_formatted = format_key(key_code)

        try:
            cursor.execute('''
                INSERT INTO license_keys
                (key_code, key_formatted, customer_name, customer_email, days, created_by, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (key_code, key_formatted, customer_name, customer_email, days, created_by, notes))

            generated_keys.append({
                "key_code": key_code,
                "key_formatted": key_formatted,
                "days": days,
                "is_lifetime": days == -1
            })
        except sqlite3.IntegrityError:
            key_code = generate_key()
            key_formatted = format_key(key_code)
            cursor.execute('''
                INSERT INTO license_keys
                (key_code, key_formatted, customer_name, customer_email, days, created_by, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (key_code, key_formatted, customer_name, customer_email, days, created_by, notes))
            generated_keys.append({
                "key_code": key_code,
                "key_formatted": key_formatted,
                "days": days,
                "is_lifetime": days == -1
            })

    conn.commit()
    conn.close()

    for gk in generated_keys:
        log_action(gk['key_code'], "key_generated", f"By: {created_by}, Days: {days}")

    return jsonify({
        "success": True,
        "message": f"{len(generated_keys)} key(s) gerada(s)",
        "keys": generated_keys
    })

@app.route('/api/admin/keys/<key_code>/revoke', methods=['POST'])
@require_admin
def revoke_key_route(key_code):
    """Revoga uma key"""
    digits = ''.join(c for c in key_code if c.isdigit())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE license_keys SET revoked = 1, revoked_at = ? WHERE key_code = ?',
        (datetime.now().isoformat(), digits)
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_action(digits, "key_revoked", "Via admin API")
        return jsonify({"success": True, "message": "Key revogada"})
    else:
        return jsonify({"success": False, "error": "Key não encontrada"}), 404

@app.route('/api/admin/keys/<key_code>/delete', methods=['DELETE'])
@require_admin
def delete_key_route(key_code):
    """Deleta uma key"""
    digits = ''.join(c for c in key_code if c.isdigit())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM license_keys WHERE key_code = ?', (digits,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_action(digits, "key_deleted", "Via admin API")
        return jsonify({"success": True, "message": "Key deletada"})
    else:
        return jsonify({"success": False, "error": "Key não encontrada"}), 404

@app.route('/api/admin/keys/<key_code>/reset-hwid', methods=['POST'])
@require_admin
def reset_hwid_route(key_code):
    """Reseta o HWID de uma key"""
    digits = ''.join(c for c in key_code if c.isdigit())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE license_keys SET hwid = "", activated = 0, activated_at = NULL, expires_at = NULL WHERE key_code = ?',
        (digits,)
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        log_action(digits, "hwid_reset", "Via admin API")
        return jsonify({"success": True, "message": "HWID resetado"})
    else:
        return jsonify({"success": False, "error": "Key não encontrada"}), 404

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def get_stats():
    """Retorna estatísticas"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM license_keys')
    total = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM license_keys WHERE revoked = 0 AND activated = 1')
    active = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM license_keys WHERE revoked = 0 AND activated = 0')
    unused = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM license_keys WHERE revoked = 1')
    revoked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM license_keys WHERE days != -1 AND expires_at IS NOT NULL AND expires_at < datetime('now')")
    expired = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM license_keys WHERE days = -1')
    lifetime = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM usage_logs')
    total_logs = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        "success": True,
        "stats": {
            "total_keys": total,
            "active_keys": active,
            "unused_keys": unused,
            "revoked_keys": revoked,
            "expired_keys": expired,
            "lifetime_keys": lifetime,
            "total_logs": total_logs
        }
    })

@app.route('/api/admin/logs', methods=['GET'])
@require_admin
def get_logs():
    """Retorna logs de uso"""
    limit = int(request.args.get('limit', 50))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM usage_logs ORDER BY created_at DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id": row['id'],
            "key_code": row['key_code'],
            "action": row['action'],
            "ip_address": row['ip_address'],
            "hwid": row['hwid'],
            "details": row['details'],
            "created_at": row['created_at']
        })

    return jsonify({"success": True, "logs": logs})

# ─────────────────────────────────────────────────────────────────────────────
# ROTA PARA DISCORD BOT
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/discord/generate', methods=['POST'])
def discord_generate():
    """Endpoint para o bot Discord gerar keys"""
    data = request.get_json()
    bot_secret = data.get('bot_secret', '')

    if bot_secret != ADMIN_SECRET:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    customer = data.get('customer', '')
    days = data.get('days', -1)
    created_by = data.get('created_by', 'discord-bot')

    key_code = generate_key()
    key_formatted = format_key(key_code)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO license_keys
        (key_code, key_formatted, customer_name, days, created_by)
        VALUES (?, ?, ?, ?, ?)
    ''', (key_code, key_formatted, customer, days, created_by))
    conn.commit()
    conn.close()

    log_action(key_code, "key_generated", f"Discord bot - {created_by}")

    return jsonify({
        "success": True,
        "key_code": key_code,
        "key_formatted": key_formatted,
        "days": days
    })

@app.route('/api/discord/validate', methods=['POST'])
def discord_validate():
    """Endpoint para o bot Discord validar keys"""
    data = request.get_json()
    key_input = data.get('key', '')
    digits = ''.join(c for c in key_input if c.isdigit())

    if not validate_key_checksum(digits):
        return jsonify({"success": False, "error": "Checksum inválido"})

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM license_keys WHERE key_code = ?', (digits,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Key não encontrada"})

    return jsonify({
        "success": True,
        "key_formatted": row['key_formatted'],
        "customer": row['customer_name'],
        "days": row['days'],
        "activated": bool(row['activated']),
        "revoked": bool(row['revoked'])
    })

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# Inicializar banco ao importar (necessário para gunicorn)
init_db()

if __name__ == '__main__':
    print("=" * 60)
    print("  ZORV License Server v2.0.0")
    print("=" * 60)
    print(f"  Database: {DB_PATH}")
    print(f"  Environment: {'Render' if IS_RENDER else 'Local'}")
    print(f"  Port: {PORT}")
    print("=" * 60)

    app.run(host='0.0.0.0', port=PORT, debug=not IS_RENDER)
