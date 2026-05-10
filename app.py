import re
import os
import time
from datetime import datetime, timedelta
from urllib.parse import unquote
from flask import Flask, request, abort, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from collections import deque

# ==========================================
# SENTINEL v4.3.1 - HARDENED WAF ENGINE
# ==========================================
RULES = {

# =========================
# SQL Injection
# =========================
"SQL_INJECTION": [
    r"(?i)\bunion\s+select\b",
    r"(?i)\bor\s+1=1\b",
    r"(?i)\band\s+1=1\b",
    r"(?i)sleep\s*\(",
    r"(?i)benchmark\s*\(",
    r"(?i)\bselect\s+.*\bfrom\b",
    r"(?i)\binsert\s+into\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\bupdate\s+.*\bset\b",
    r"(?i)information_schema",
    r"(?i)xp_cmdshell",
    r"(?i)--",
    r"(?i)#"
],

# =========================
# XSS (Improved)
# =========================
"XSS": [
    r"(?i)<script.*?>",
    r"(?i)javascript:",
    r"(?i)onerror=",
    r"(?i)onload=",
    r"(?i)<img.*?>",
    r"(?i)<iframe.*?>",
    r"(?i)<svg.*?>",
    r"(?i)alert\s*\(",
    r"(?i)document\.cookie",
    r"(?i)window\.location"
],

# =========================
# RCE / Command Injection
# =========================
"RCE": [
    r";\s*cat\s+/etc/passwd",
    r";\s*ls",
    r";\s*whoami",
    r";\s*id",
    r"\|\s*whoami",
    r"\|\s*curl",
    r"\|\s*wget",
    r"&&\s*id",
    r"system\s*\(",
    r"exec\s*\(",
    r"passthru\s*\(",
    r"shell_exec\s*\("
],

# =========================
# Path Traversal
# =========================
"PATH_TRAVERSAL": [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/proc/self/environ",
    r"boot\.ini",
    r"win\.ini"
],

# =========================
# File Inclusion
# =========================
"FILE_INCLUSION": [
    r"php://",
    r"file://",
    r"data://",
    r"expect://"
],

# =========================
# Sensitive Files
# =========================
"SENSITIVE_FILE": [
    r"\.env",
    r"\.git",
    r"\.htaccess",
    r"\.htpasswd",
    r"config\.php",
    r"wp-config\.php"
],

# =========================
# Webshell
# =========================
"WEBSHELL": [
    r"cmd\.php",
    r"shell\.php",
    r"c99\.php",
    r"r57\.php",
    r"webshell"
],

# =========================
# PHP Injection
# =========================
"PHP_INJECTION": [
    r"<\?php",
    r"eval\s*\(",
    r"base64_decode\s*\(",
    r"assert\s*\("
],

# =========================
# Scanner Detection (LOW)
# =========================
"SCANNER": [
    r"sqlmap",
    r"nikto",
    r"acunetix",
    r"nessus",
    r"nmap",
    r"burp"
],

# =========================
# Session Attacks
# =========================
"SESSION_ATTACK": [
    r"phpsessid=",
    r"jsessionid=",
    r"asp\.net_sessionid"
],

# =========================
# Encoding Attacks
# =========================
"ENCODING_ATTACK": [
    r"%2e%2e%2f",
    r"%252e%252e",
    r"%3cscript%3e"
],

# =========================
# Request Smuggling
# =========================
"REQUEST_SMUGGLING": [
    r"%0d%0a",
    r"\r\n\r\n"
],

# =========================
# Data Leak
# =========================
"DATA_LEAK": [
    r"(?i)index of /",
    r"(?i)directory listing",
    r"(?i)stack trace"
],

# =========================
# Protocol Issues
# =========================
"PROTOCOL_VIOLATION": [
    r"http/1\.[2-9]",
    r"transfer-encoding:\s*chunked"
],

# =========================
# Bad User Agents
# =========================
"BAD_USER_AGENT": [
    r"(?i)^curl",
    r"(?i)^wget",
    r"(?i)python-requests"
],

# =========================
# SSRF (SAFE VERSION)
# =========================
"SSRF": [
    r"(?i)http://127\.0\.0\.1",
    r"(?i)http://localhost",
    r"169\.254\.169\.254"
]

}

HIGH_RISK = ["RCE", "WEBSHELL", "FILE_INCLUSION", "PATH_TRAVERSAL", "PHP_INJECTION", "SENSITIVE_FILE"]
MEDIUM_RISK = ["SQL_INJECTION", "XSS", "SSRF", "SESSION_ATTACK", "ENCODING_ATTACK", "REQUEST_SMUGGLING"]
PRIORITY = HIGH_RISK + MEDIUM_RISK + ["SCANNER", "DATA_LEAK", "PROTOCOL_VIOLATION", "BAD_USER_AGENT"]
COMPILED_RULES = {k: [re.compile(p) for p in v] for k, v in RULES.items()}
SAFE_PATHS = ['/api/stats', '/dashboard', '/favicon.ico']

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'sentinel_v5.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {"timeout": 5}
}
db = SQLAlchemy(app)

ip_qps = {}
last_cleanup = time.time()

class WafLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.now)
    ip = db.Column(db.String(45))
    status = db.Column(db.Integer)
    attack = db.Column(db.String(255))
    target = db.Column(db.String(255))
    os_info = db.Column(db.String(50))
    browser = db.Column(db.String(50))
    payload = db.Column(db.Text)

class BlockedIP(db.Model):
    ip = db.Column(db.String(45), primary_key=True)
    unban_at = db.Column(db.DateTime)
    
def block_ip(ip, minutes):
    try:
        existing = BlockedIP.query.filter_by(ip=ip).first()

        new_time = datetime.now() + timedelta(minutes=minutes)
        if existing:
            if existing.unban_at < new_time:
                existing.unban_at = new_time
        else:
            db.session.add(
                BlockedIP(ip=ip, unban_at=new_time)
            )
        db.session.flush()  # force DB write early

    except IntegrityError:
        db.session.rollback()

        # Retry update (record already exists)
        existing = BlockedIP.query.filter_by(ip=ip).first()
        if existing:
            existing.unban_at = datetime.now() + timedelta(minutes=minutes)

def get_fingerprint(ua):
    ua = (ua or "Unknown").lower()
    os_bit = "Windows" if "win" in ua else "Linux" if "linux" in ua else "Android" if "android" in ua else "iOS" if "iphone" in ua else "macOS" if "mac" in ua  else "CLI" if "curl" in ua else "Other"
    browser_bit = "Chrome" if "chrome" in ua else "Firefox" if "firefox" in ua else "Safari" if "safari" in ua else "Bot" if any(x in ua for x in ["bot","curl","python"]) else "Generic"
    return os_bit, browser_bit

def inspect_request(req):
    raw_body = req.get_data(as_text=True) or ""
    headers = " ".join([f"{k}:{v}" for k, v in req.headers.items()]).lower()
    path = unquote(req.full_path.lower())
    body = unquote(raw_body.lower())
    detected = []
    for attack_name in PRIORITY:
        for p in COMPILED_RULES[attack_name]:
            if p.search(path) or p.search(body) or p.search(headers):
                detected.append(attack_name)
                break 
    return detected

def log_event(status, attack=None):
    request._logged = True
    ua = request.headers.get('User-Agent', 'Unknown')
    os_info, br = get_fingerprint(ua)
    body = request.get_data(cache=True, as_text=True)[:1000]
    new_log = WafLog(
        ip=request.remote_addr, status=status,
        attack=attack or "Clean Traffic", target=request.path,
        os_info=os_info, browser=br,
        payload=f"[{request.method}] {request.full_path} | Body: {body}"
    )
    db.session.add(new_log)

@app.before_request
def waf_engine():
    global last_cleanup
    request._logged = False
    
    if request.path in SAFE_PATHS or request.path.startswith('/static'): 
        return
    ip, now = request.remote_addr, datetime.now()
    blocked = BlockedIP.query.filter_by(ip=ip).first()
    if blocked:
        if blocked.unban_at > now:
            return abort(403)   # STOP everything immediately
        else:
            db.session.delete(blocked)
            db.session.commit()
    
    
    # Cleanup only sometimes (every ~10 sec)
    if time.time() - last_cleanup > 10:
        try:
            WafLog.query.filter(
                WafLog.ts < now - timedelta(hours=24)
            ).delete(synchronize_session=False)
            
            BlockedIP.query.filter(BlockedIP.unban_at < now).delete(synchronize_session=False)
            
            now_ts = time.time()
            for old_ip in list(ip_qps.keys()):
                if not ip_qps[old_ip] or (now_ts - ip_qps[old_ip][-1] > 60):
                    del ip_qps[old_ip]
            

            db.session.commit()
            last_cleanup = time.time()
        except:
            db.session.rollback()
   
    
        
   
    
    # ==============================
# Sliding Window Rate Limit
# ==============================
    window_size = 2   # seconds
    threshold = 15   # requests allowed

    curr_t = time.time()

    if ip not in ip_qps:
        ip_qps[ip] = deque()

    ip_qps[ip].append(curr_t)

# Remove old requests
    while ip_qps[ip] and curr_t - ip_qps[ip][0] > window_size:
        ip_qps[ip].popleft()

# Check limit
    if len(ip_qps[ip]) > threshold:
       block_ip(ip, 2)
    
       log_event(429, "Sliding Window Rate Limit")
       db.session.commit()
       abort(429)

    # DPI Inspection
    detections = inspect_request(request)
    if detections:
        atk_str = ", ".join(detections)
        if any(d in HIGH_RISK for d in detections):
            block_ip(ip, 5)
        
            log_event(403, f"[HIGH] {atk_str}")
            db.session.commit()
            abort(403)
        log_event(403, f"[MED] {atk_str}") if any(d in MEDIUM_RISK for d in detections) else log_event(200, f"[LOW] {atk_str}")
        db.session.commit()
        if any(d in MEDIUM_RISK for d in detections): abort(403)

@app.after_request
def audit(response):
    if response.status_code == 200 and not (request.path in SAFE_PATHS or request.path.startswith('/static')):
        
        # Only log if NOTHING was logged before
        if not getattr(request, "_logged", False):
            pass

        db.session.commit()
    return response

@app.route('/', methods=['GET', 'POST'])

def home(): return "<h1>🛡️ Sentinel Active</h1>"

@app.route('/dashboard')
def dash(): return render_template('dash3.html')

@app.route('/api/stats')
def api_stats():
    now = datetime.now()
    history = []
    for i in range(10, 0, -1):
        et, st = now - timedelta(seconds=(i-1)*10), now - timedelta(seconds=i*10)
        history.append({
            "t": et.strftime("%H:%M:%S"),
            "total": WafLog.query.filter(WafLog.ts.between(st, et)).count(),
            "attacks": WafLog.query.filter(WafLog.ts.between(st, et), WafLog.status != 200).count()
        })
    
    logs = WafLog.query.filter(WafLog.status != 200)\
    .order_by(WafLog.ts.desc()).limit(15).all()
    return jsonify({
        "counts": {"access_ip": db.session.query(WafLog.ip).distinct().count(), "attack_ip": db.session.query(WafLog.ip).filter(WafLog.status != 200).distinct().count(), "active_bans": BlockedIP.query.count()},
        "metrics": {"200": WafLog.query.filter_by(status=200).count(), "403": WafLog.query.filter_by(status=403).count(), "429": WafLog.query.filter_by(status=429).count()},
        "history": history,
        "intel": {"os": dict(db.session.query(WafLog.os_info, func.count(WafLog.id)).group_by(WafLog.os_info).all()), "browsers": dict(db.session.query(WafLog.browser, func.count(WafLog.id)).group_by(WafLog.browser).all()), "active_bans": [b.ip for b in BlockedIP.query.all()]},
        "logs": [{"ts": l.ts.strftime("%H:%M:%S"), "ip": l.ip, "attack": l.attack, "target": l.target, "payload": l.payload} for l in logs]
    })

if __name__ == '__main__':
     with app.app_context():
        db.create_all()
        db.session.execute(text("PRAGMA journal_mode=WAL;"))
        db.session.commit()

     app.run(port=5000)
   
