"""
SecureLogin — 웹 층 (로그인 사이트 + 실패 제한 + 이벤트 기록 + 관리자 대시보드)

실행:
    python3 app.py init     # DB 생성 + 관리자/시연용 계정 만들기 (처음 한 번)
    python3 app.py run      # 서버 실행 (기본 0.0.0.0:8080)

※ 격리된 실습 VM에서만 사용하세요.
"""
import csv
import io
import logging
import os
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from functools import wraps
from getpass import getpass

from flask import (Flask, Response, abort, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ─────────────────────────────────────────────
# 설정값 (필요하면 여기만 바꾸면 됩니다)
# ─────────────────────────────────────────────
MAX_FAIL_PER_ACCOUNT = 5    # 계정 하나당 허용 실패 횟수
ACCOUNT_WINDOW_MIN = 10     # 위 횟수를 세는 시간 범위(분)
ACCOUNT_LOCK_MIN = 5        # 계정 잠금 시간(분)

MAX_FAIL_PER_IP = 20        # IP 하나당 허용 실패 횟수 (여러 계정을 돌려가며 공격하는 경우 대비)
IP_WINDOW_MIN = 10
IP_BLOCK_MIN = 10

HOST = os.environ.get("SL_HOST", "0.0.0.0")
PORT = int(os.environ.get("SL_PORT", "8080"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SL_DB", os.path.join(BASE_DIR, "securelogin.db"))
KEY_PATH = os.path.join(BASE_DIR, ".secret_key")
LOG_PATH = os.path.join(BASE_DIR, "securelogin_events.log")

KST = timezone(timedelta(hours=9))
TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

ATTEMPT_RESULTS = ("success", "fail", "locked", "blocked_ip")   # 실제 로그인 시도
ACTION_RESULTS = ("lock_account", "block_ip")                  # 방어 장치가 작동한 기록

# 관리자가 대시보드를 보려고 로그인한 기록은 비교표·그래프에서 뺀다 (이벤트 로그에는 남음)
NOT_ADMIN_OK = ("NOT (result='success' AND username IN "
                "(SELECT username FROM users WHERE role='admin'))")

RESULT_LABELS = {
    "success": ("성공", "ok"),
    "fail": ("실패", "warn"),
    "locked": ("잠금 거부", "block"),
    "blocked_ip": ("IP 차단 거부", "block"),
    "lock_account": ("계정 잠금 발동", "action"),
    "block_ip": ("IP 차단 발동", "action"),
}

# ─────────────────────────────────────────────
# 앱 기본 설정
# ─────────────────────────────────────────────
def load_secret_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# 이벤트를 텍스트 로그 파일로도 남김 (Snort 경보 시각과 맞춰 보기 좋게)
event_logger = logging.getLogger("securelogin")
event_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(message)s"))
event_logger.addHandler(_fh)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT,
    result TEXT NOT NULL,
    defense TEXT NOT NULL,
    round TEXT NOT NULL,
    detail TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username, result, ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, result, ts);
CREATE TABLE IF NOT EXISTS locks (
    kind TEXT NOT NULL,          -- 'account' 또는 'ip'
    key TEXT NOT NULL,
    until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


# ─────────────────────────────────────────────
# 공통 함수
# ─────────────────────────────────────────────
def now():
    return datetime.now(timezone.utc)


def ts(dt):
    return dt.strftime(TS_FMT)


def parse_ts(s):
    return datetime.strptime(s, TS_FMT).replace(tzinfo=timezone.utc)


def to_kst(s, fmt="%m-%d %H:%M:%S"):
    if not s:
        return ""
    dt = parse_ts(s) if isinstance(s, str) else s
    return dt.astimezone(KST).strftime(fmt)


app.jinja_env.filters["kst"] = to_kst


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def get_setting(k, default=None):
    row = db().execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return row["v"] if row else default


def set_setting(k, v):
    db().execute("INSERT OR REPLACE INTO settings(k, v) VALUES(?, ?)", (k, v))
    db().commit()


def client_ip():
    return request.remote_addr or "unknown"


def log_event(username, result, detail=""):
    t = now()
    defense = get_setting("defense", "off")
    rnd = get_setting("round", "기본")
    ip = client_ip()
    db().execute(
        "INSERT INTO events(ts, ip, username, result, defense, round, detail, user_agent)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (ts(t), ip, username, result, defense, rnd, detail,
         (request.headers.get("User-Agent") or "")[:200]),
    )
    db().commit()
    event_logger.info(
        f"{t.astimezone(KST).strftime('%Y-%m-%d %H:%M:%S')} KST ip={ip} user={username} "
        f"result={result} defense={defense} round={rnd} {detail}".rstrip()
    )


# ─── 잠금/차단 ───
def active_lock(kind, key):
    row = db().execute("SELECT until FROM locks WHERE kind=? AND key=?", (kind, key)).fetchone()
    if row:
        until = parse_ts(row["until"])
        if until > now():
            return until
    return None


def set_lock(kind, key, minutes):
    until = now() + timedelta(minutes=minutes)
    db().execute(
        "INSERT OR REPLACE INTO locks(kind, key, until, created_at) VALUES(?,?,?,?)",
        (kind, key, ts(until), ts(now())),
    )
    db().commit()
    return until


def recent_fail_count(kind, key, window_min):
    """최근 window_min분 안의 실패 횟수. 지난 잠금이 풀린 뒤 / 마지막 성공 뒤부터만 센다."""
    since = now() - timedelta(minutes=window_min)
    row = db().execute("SELECT until FROM locks WHERE kind=? AND key=?", (kind, key)).fetchone()
    if row:
        since = max(since, parse_ts(row["until"]))
    col = "username" if kind == "account" else "ip"
    if kind == "account":
        last_ok = db().execute(
            "SELECT MAX(ts) t FROM events WHERE result='success' AND username=?", (key,)
        ).fetchone()["t"]
        if last_ok:
            since = max(since, parse_ts(last_ok))
    return db().execute(
        f"SELECT COUNT(*) c FROM events WHERE result='fail' AND {col}=? AND ts>?",
        (key, ts(since)),
    ).fetchone()["c"]


def remaining_text(until):
    sec = max(0, int((until - now()).total_seconds()))
    m, s = divmod(sec, 60)
    return f"{m}분 {s}초" if m else f"{s}초"


# ─── CSRF (관리자 화면 폼 보호) ───
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    token = request.form.get("csrf")
    if not token or token != session.get("csrf"):
        abort(400)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────
# 로그인
# ─────────────────────────────────────────────
DUMMY_HASH = generate_password_hash("timing-equalizer-dummy")


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()[:64]
    password = request.form.get("password") or ""
    if not username or not password:
        return render_template("login.html", error="아이디와 비밀번호를 입력해 주세요.", username=username)

    defense_on = get_setting("defense", "off") == "on"
    ip = client_ip()

    # 1) 방어 ON이면, 비밀번호를 확인하기 전에 잠금/차단부터 검사
    if defense_on:
        until = active_lock("ip", ip)
        if until:
            log_event(username, "blocked_ip", f"IP 차단 중(남은 {remaining_text(until)})")
            return render_template("login.html", username=username, state="block",
                                   error=f"이 IP는 로그인 실패가 너무 많아 일시 차단되었습니다. {remaining_text(until)} 후 다시 시도해 주세요.")
        until = active_lock("account", username)
        if until:
            log_event(username, "locked", f"계정 잠금 중(남은 {remaining_text(until)})")
            return render_template("login.html", username=username, state="block",
                                   error=f"로그인 실패가 반복되어 계정이 잠겼습니다. {remaining_text(until)} 후 다시 시도해 주세요.")

    # 2) 비밀번호 확인 (없는 아이디도 같은 시간이 걸리도록 더미 해시로 비교)
    user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    pw_ok = check_password_hash(user["pw_hash"] if user else DUMMY_HASH, password)

    if user and pw_ok:
        log_event(username, "success")
        session.clear()
        session["uid"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return render_template("welcome.html", user=user)

    # 3) 실패 처리
    log_event(username, "fail")
    msg = "아이디 또는 비밀번호가 올바르지 않습니다."
    state = None
    if defense_on:
        n = recent_fail_count("account", username, ACCOUNT_WINDOW_MIN)
        if n >= MAX_FAIL_PER_ACCOUNT:
            set_lock("account", username, ACCOUNT_LOCK_MIN)
            log_event(username, "lock_account", f"{n}회 실패 → {ACCOUNT_LOCK_MIN}분 잠금")
            msg = f"로그인 실패가 {n}회 반복되어 계정이 {ACCOUNT_LOCK_MIN}분간 잠겼습니다."
            state = "block"
        else:
            msg += f" (잠금까지 남은 시도 {MAX_FAIL_PER_ACCOUNT - n}회)"

        m = recent_fail_count("ip", ip, IP_WINDOW_MIN)
        if m >= MAX_FAIL_PER_IP:
            set_lock("ip", ip, IP_BLOCK_MIN)
            log_event(username, "block_ip", f"IP {ip} {m}회 실패 → {IP_BLOCK_MIN}분 차단")

    return render_template("login.html", error=msg, username=username, state=state)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# 관리자 대시보드
# ─────────────────────────────────────────────
def comparison_rows():
    q_marks = ",".join("?" * len(ATTEMPT_RESULTS))
    rows = db().execute(
        f"""SELECT round, defense,
                   COUNT(*) attempts,
                   SUM(result='success') success,
                   SUM(result='fail') fail,
                   SUM(result IN ('locked','blocked_ip')) rejected,
                   COUNT(DISTINCT ip) ips,
                   MIN(ts) first_ts, MAX(ts) last_ts,
                   GROUP_CONCAT(DISTINCT CASE WHEN result='success' THEN username END) breached
            FROM events WHERE result IN ({q_marks}) AND {NOT_ADMIN_OK}
            GROUP BY round, defense ORDER BY MIN(ts)""",
        ATTEMPT_RESULTS,
    ).fetchall()
    actions = {
        (r["round"], r["defense"]): r["c"]
        for r in db().execute(
            "SELECT round, defense, COUNT(*) c FROM events "
            "WHERE result IN ('lock_account','block_ip') GROUP BY round, defense"
        )
    }
    out = []
    for r in rows:
        d = dict(r)
        d["actions"] = actions.get((r["round"], r["defense"]), 0)
        dur = (parse_ts(r["last_ts"]) - parse_ts(r["first_ts"])).total_seconds()
        d["duration"] = round(dur, 1)
        d["rate"] = round(r["attempts"] / dur, 1) if dur > 0 else None
        d["block_ratio"] = round(100 * r["rejected"] / r["attempts"]) if r["attempts"] else 0
        out.append(d)
    return out


def minute_bars(minutes=30):
    start = now().replace(second=0, microsecond=0) - timedelta(minutes=minutes - 1)
    q_marks = ",".join("?" * len(ATTEMPT_RESULTS))
    data = {
        r["m"]: r
        for r in db().execute(
            f"""SELECT substr(ts,1,16) m, COUNT(*) total,
                       SUM(result IN ('locked','blocked_ip')) rejected,
                       SUM(result='success') success
                FROM events WHERE ts>=? AND result IN ({q_marks}) AND {NOT_ADMIN_OK} GROUP BY m""",
            (ts(start), *ATTEMPT_RESULTS),
        )
    }
    bars = []
    for i in range(minutes):
        t = start + timedelta(minutes=i)
        key = t.strftime("%Y-%m-%d %H:%M")
        r = data.get(key)
        bars.append({
            "label": t.astimezone(KST).strftime("%H:%M"),
            "total": r["total"] if r else 0,
            "rejected": r["rejected"] if r else 0,
            "success": r["success"] if r else 0,
        })
    peak = max([b["total"] for b in bars] + [1])
    for b in bars:
        b["h"] = round(100 * b["total"] / peak)
        b["rh"] = round(100 * b["rejected"] / peak)
    return bars, peak


@app.route("/admin")
@admin_required
def admin():
    q_marks = ",".join("?" * len(ATTEMPT_RESULTS))
    ctx = {
        "defense": get_setting("defense", "off"),
        "round": get_setting("round", "기본"),
        "comparison": comparison_rows(),
        "events": db().execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall(),
        "locks": db().execute("SELECT * FROM locks WHERE until>? ORDER BY until DESC", (ts(now()),)).fetchall(),
        "top_ips": db().execute(
            f"SELECT ip, COUNT(*) c, SUM(result='fail') f FROM events WHERE result IN ({q_marks}) AND {NOT_ADMIN_OK} "
            "GROUP BY ip ORDER BY c DESC LIMIT 5", ATTEMPT_RESULTS).fetchall(),
        "total": db().execute("SELECT COUNT(*) c FROM events").fetchone()["c"],
        "labels": RESULT_LABELS,
        "cfg": {
            "acc": MAX_FAIL_PER_ACCOUNT, "acc_win": ACCOUNT_WINDOW_MIN, "acc_lock": ACCOUNT_LOCK_MIN,
            "ip": MAX_FAIL_PER_IP, "ip_win": IP_WINDOW_MIN, "ip_lock": IP_BLOCK_MIN,
        },
    }
    ctx["bars"], ctx["peak"] = minute_bars()
    return render_template("admin.html", **ctx)


@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    check_csrf()
    defense = request.form.get("defense")
    if defense in ("on", "off"):
        set_setting("defense", defense)
    rnd = (request.form.get("round") or "").strip()[:40]
    if rnd:
        set_setting("round", rnd)
    return redirect(url_for("admin"))


@app.route("/admin/unlock", methods=["POST"])
@admin_required
def admin_unlock():
    check_csrf()
    # 잠금을 지우지 않고 '지금 풀림'으로 바꿔서, 풀린 뒤부터 실패 횟수를 다시 센다
    db().execute("UPDATE locks SET until=? WHERE until>?", (ts(now()), ts(now())))
    db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/reset", methods=["POST"])
@admin_required
def admin_reset():
    check_csrf()
    db().execute("DELETE FROM events")
    db().execute("DELETE FROM locks")
    db().commit()
    return redirect(url_for("admin"))


@app.route("/admin/export.csv")
@admin_required
def admin_export():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["시각(KST)", "IP", "아이디", "결과", "방어", "라운드", "상세", "User-Agent"])
    for e in db().execute("SELECT * FROM events ORDER BY id"):
        w.writerow([to_kst(e["ts"], "%Y-%m-%d %H:%M:%S.%f")[:-3], e["ip"], e["username"],
                    RESULT_LABELS.get(e["result"], (e["result"],))[0], e["defense"].upper(),
                    e["round"], e["detail"], e["user_agent"]])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=securelogin_events.csv"})


# ─────────────────────────────────────────────
# 명령줄 (init / adduser / run)
# ─────────────────────────────────────────────
def init_db():
    db().executescript(SCHEMA)
    if get_setting("defense") is None:
        set_setting("defense", "off")
    if get_setting("round") is None:
        set_setting("round", "기본")
    db().commit()


def upsert_user(username, password, role):
    db().execute(
        "INSERT INTO users(username, pw_hash, role, created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash, role=excluded.role",
        (username, generate_password_hash(password), role, ts(now())),
    )
    db().commit()


def ask_password(prompt):
    while True:
        p1 = getpass(prompt)
        if len(p1) < 8:
            print("  8자 이상으로 정해 주세요.")
            continue
        if getpass("  한 번 더 입력: ") != p1:
            print("  두 번 입력한 값이 다릅니다.")
            continue
        return p1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    with app.app_context():
        init_db()
        if cmd == "init":
            admin_pw = os.environ.get("SL_ADMIN_PASSWORD") or ask_password("관리자(admin) 비밀번호: ")
            upsert_user("admin", admin_pw, "admin")
            upsert_user("victim", "iloveyou", "user")
            print("✔ DB 준비 완료:", DB_PATH)
            print("✔ 관리자 계정: admin")
            print("✔ 시연용 피해자 계정: victim / iloveyou  (일부러 약한 비밀번호 — 격리 VM 전용)")
        elif cmd == "adduser":
            if len(sys.argv) < 3:
                print("사용법: python3 app.py adduser <아이디> [admin|user]")
                return
            role = sys.argv[3] if len(sys.argv) > 3 else "user"
            upsert_user(sys.argv[2], ask_password(f"{sys.argv[2]} 비밀번호: "), role)
            print("✔ 계정 저장 완료")
        elif cmd == "run":
            print(f"SecureLogin 실행 중 → http://{HOST}:{PORT}/login  (관리자: /admin)")
            app.run(host=HOST, port=PORT, threaded=True)
        else:
            print("명령: init | adduser | run")


if __name__ == "__main__":
    main()
