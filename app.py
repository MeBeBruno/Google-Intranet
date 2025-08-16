from __future__ import annotations
import os, io, secrets, base64, hashlib, mimetypes
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, jsonify, abort, Response,
    render_template, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from icalendar import Calendar as ICal, Event as ICalEvent
from dotenv import load_dotenv
import pyotp
from cryptography.fernet import Fernet
import qrcode

# =============================================================================
# Konfiguration
# =============================================================================
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = BASE_DIR / "intranet.sqlite3"

ALLOWED_EXT = {"png","jpg","jpeg","gif","mp4","mov","webm","pdf","docx","xlsx","pptx","txt"}
MAX_CONTENT_LENGTH = 128 * 1024 * 1024  # 128 MB

EXTERNAL_URL = os.environ.get("EXTERNAL_URL", "http://127.0.0.1:5000")
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-" + secrets.token_hex(32)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# =============================================================================
# Zeit-Helfer (timezone-aware)
# =============================================================================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def ensure_aware_utc(dt: datetime | None) -> datetime | None:
    """Normalisiert naive Datetimes (alt) auf UTC-aware, damit Vergleiche sicher sind."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# =============================================================================
# Krypto-Utilities (TOTP-Secret Verschlüsselung at rest)
# =============================================================================
def _fernet_key_from_secret(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

_FERNET = Fernet(_fernet_key_from_secret(SECRET_KEY))

def encrypt_str(s: str) -> str:
    return _FERNET.encrypt(s.encode("utf-8")).decode("utf-8")

def decrypt_str(s: str) -> str:
    return _FERNET.decrypt(s.encode("utf-8")).decode("utf-8")

# =============================================================================
# Datenbank-Modelle
# =============================================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    pass_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # "user" | "admin"
    totp_secret_enc = db.Column(db.Text, nullable=True)
    is_totp_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)
    storage_quota_mb = db.Column(db.Integer, default=1024)

    calendars = db.relationship("Calendar", backref="owner", lazy=True, cascade="all, delete-orphan")
    media_files = db.relationship("MediaFile", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, pw: str):
        self.pass_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.pass_hash, pw)

    def set_totp_secret(self, secret: str):
        self.totp_secret_enc = encrypt_str(secret)

    def get_totp(self) -> pyotp.TOTP | None:
        if not self.totp_secret_enc:
            return None
        try:
            secret = decrypt_str(self.totp_secret_enc)
            return pyotp.TOTP(secret)
        except Exception:
            return None

class Calendar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    visibility = db.Column(db.String(20), default="private")  # private|org
    ics_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)
    events = db.relationship("Event", backref="calendar", lazy=True, cascade="all, delete-orphan")

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    calendar_id = db.Column(db.Integer, db.ForeignKey("calendar.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    starts_at = db.Column(db.DateTime(timezone=True), nullable=False)   # UTC
    ends_at = db.Column(db.DateTime(timezone=True),   nullable=False)   # UTC
    all_day = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(200))
    description = db.Column(db.Text)
    uid = db.Column(db.String(120), unique=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)
    updated_at = db.Column(db.DateTime(timezone=True), default=now_utc, onupdate=now_utc)

class MediaFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    mimetype = db.Column(db.String(100))
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256_hex = db.Column(db.String(64), index=True)
    data = db.Column(db.LargeBinary, nullable=False)  # BLOB
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)

class InviteToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(255), nullable=False, index=True)  # nur Hash, nie Klartext speichern
    role = db.Column(db.String(20), default="user")       # "user" | "admin"
    uses_remaining = db.Column(db.Integer, default=1)
    purpose = db.Column(db.String(20), default="invite")  # "invite" | "bootstrap"
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

# =============================================================================
# Helpers
# =============================================================================
@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))

@app.before_request
def sqlite_pragmas_and_2fa_gate():
    # SQLite: sichere Defaults
    if db.engine.name == "sqlite":
        with db.engine.connect() as con:
            con.exec_driver_sql("PRAGMA journal_mode=WAL;")
            con.exec_driver_sql("PRAGMA foreign_keys=ON;")
    # 2FA Gate: erst 2FA abschließen
    allowed = {"setup_2fa", "logout", "static", "login", "register", "calendar_ics"}
    if current_user.is_authenticated and not current_user.is_totp_confirmed:
        endpoint = (request.endpoint or "").split(".")[-1]
        if endpoint not in allowed:
            return redirect(url_for("setup_2fa"))

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXT

def hash_token(code: str) -> str:
    return generate_password_hash(code)

def verify_token_hash(stored_hash: str, code: str) -> bool:
    return check_password_hash(stored_hash, code)

# --- QR-Routinen --------------------------------------------------------------
def ascii_qr_halfheight(text: str) -> str:
    """
    Kompakter ASCII-QR: nutzt Halbblock-Zeichen, um 2 QR-Zeilen auf 1 Terminalzeile
    zu packen. Zeichen: '█' (beide), '▀' (oben), '▄' (unten), ' ' (keine).
    """
    qr = qrcode.QRCode(border=1, box_size=1)
    qr.add_data(text)
    qr.make(fit=True)
    m = qr.get_matrix()  # bool-Matrix
    lines = []
    h = len(m)
    w = len(m[0])
    for y in range(0, h, 2):
        upper = m[y]
        lower = m[y+1] if y+1 < h else [False]*w
        row_chars = []
        for u, l in zip(upper, lower):
            if u and l:
                ch = "█"
            elif u and not l:
                ch = "▀"
            elif not u and l:
                ch = "▄"
            else:
                ch = " "
            row_chars.append(ch)
        lines.append("".join(row_chars))
    return "\n".join(lines)

def qr_png_data_uri(text: str, box_size: int = 6) -> str:
    """PNG-QR als Data-URI für HTML."""
    qr = qrcode.QRCode(border=1, box_size=box_size)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def print_bootstrap_instructions(link: str, code: str):
    banner = "="*72
    print("\n" + banner)
    print(" ⚙️  ERSTKONFIGURATION – Admin-Registrierung")
    print(f" Link: {link}")
    print(f" Code: {code}\n")
    # Nur Konsole (ASCII, halbierte Höhe dank Halbblock-Zeichen)
    print(ascii_qr_halfheight(link))
    print(banner + "\n")

def ensure_bootstrap_token_and_print():
    # Wenn noch kein Admin existiert → Bootstrap-Token erzeugen und in Konsole anzeigen
    have_admin = db.session.query(User).filter_by(role="admin").count() > 0
    if have_admin:
        return
    code = secrets.token_urlsafe(18)
    token = InviteToken(
        code_hash=hash_token(code),
        role="admin",
        uses_remaining=1,
        purpose="bootstrap",
        expires_at=now_utc() + timedelta(days=2),
        created_by_user_id=None
    )
    db.session.add(token); db.session.commit()
    link = f"{EXTERNAL_URL}/register?invite={code}&role=admin"
    print_bootstrap_instructions(link, code)

def user_used_bytes(user_id: int) -> int:
    return db.session.query(db.func.coalesce(db.func.sum(MediaFile.size_bytes), 0)).filter_by(user_id=user_id).scalar()

def sha256_hex_of_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

# =============================================================================
# Routen – Public / Auth
# =============================================================================
@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

# Registrierung (Invite-Code Pflicht, Prefill via ?invite=)
@app.route("/register", methods=["GET","POST"])
def register():
    invite_prefill = request.args.get("invite","")
    role_hint = request.args.get("role","user")

    if request.method == "POST":
        username = request.form.get("username","").strip()
        email    = request.form.get("email","").strip() or None
        password = request.form.get("password","")
        invite   = request.form.get("invite_code","").strip()

        if not (username and password and invite):
            flash("Bitte alle Pflichtfelder ausfüllen (inkl. Invite-Code).", "error")
        else:
            token = None
            for t in InviteToken.query.order_by(InviteToken.created_at.desc()).all():
                if t.uses_remaining <= 0:
                    continue
                exp = ensure_aware_utc(t.expires_at)
                if exp and now_utc() > exp:
                    continue
                if verify_token_hash(t.code_hash, invite):
                    token = t
                    break
            if not token:
                flash("Ungültiger oder abgelaufener Invite-Code.", "error")
            else:
                if token.purpose == "bootstrap":
                    have_admin = db.session.query(User).filter_by(role="admin").count() > 0
                    if have_admin:
                        flash("Bootstrap-Token ist nicht mehr gültig.", "error")
                        token = None

            if token:
                if User.query.filter_by(username=username).first():
                    flash("Username bereits vergeben.", "error")
                elif email and User.query.filter_by(email=email).first():
                    flash("E-Mail bereits registriert.", "error")
                else:
                    u = User(username=username, email=email, role=token.role)
                    u.set_password(password)
                    secret = pyotp.random_base32()
                    u.set_totp_secret(secret)
                    u.is_totp_confirmed = False
                    db.session.add(u)
                    db.session.flush()  # u.id verfügbar

                    cal = Calendar(
                        name="Organisation" if u.role=="admin" else f"{u.username}",
                        owner_id=u.id,
                        visibility="org" if u.role=="admin" else "private",
                        ics_token=secrets.token_hex(20)
                    )
                    db.session.add(cal)

                    token.uses_remaining -= 1
                    db.session.commit()

                    login_user(u)
                    flash("Konto erstellt. Bitte 2FA einrichten.", "success")
                    return redirect(url_for("setup_2fa"))

    return render_template("register.html", invite_prefill=invite_prefill, role_hint=role_hint)

# 2FA Setup (verpflichtend)
@app.route("/setup-2fa", methods=["GET","POST"])
@login_required
def setup_2fa():
    if current_user.is_totp_confirmed and current_user.get_totp():
        return redirect(url_for("dashboard"))
    totp = current_user.get_totp()
    if not totp:
        secret = pyotp.random_base32()
        current_user.set_totp_secret(secret)
        db.session.commit()
        totp = current_user.get_totp()

    issuer = "Intranet"
    label = f"{issuer}:{current_user.username}"
    otpauth = totp.provisioning_uri(name=label, issuer_name=issuer)

    # QR als PNG (Data-URI) für die Seite
    qr_data_uri = qr_png_data_uri(otpauth, box_size=6)

    if request.method == "POST":
        code = request.form.get("code","").strip()
        if totp.verify(code, valid_window=1):
            current_user.is_totp_confirmed = True
            db.session.commit()
            flash("2FA erfolgreich eingerichtet.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("TOTP-Code ungültig. Bitte erneut versuchen.", "error")

    return render_template("setup_2fa.html", qr_data_uri=qr_data_uri, otpauth=otpauth)

# Login (mit TOTP)
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        totp_code = request.form.get("totp","").strip()

        u = User.query.filter_by(username=username).first()
        if not u or not u.check_password(password):
            flash("Login fehlgeschlagen.", "error")
        else:
            if not (u.is_totp_confirmed and u.get_totp()):
                flash("2FA ist noch nicht eingerichtet. Bitte zuerst 2FA einrichten.", "error")
                login_user(u)
                return redirect(url_for("setup_2fa"))

            totp = u.get_totp()
            if not totp or not totp.verify(totp_code, valid_window=1):
                flash("TOTP-Code ungültig.", "error")
            else:
                login_user(u)
                return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# =============================================================================
# Dashboard / Profil
# =============================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    cal = Calendar.query.filter_by(owner_id=current_user.id).first()
    if not cal:
        cal = Calendar(name=f"{current_user.username}", owner_id=current_user.id,
                       visibility="private", ics_token=secrets.token_hex(20))
        db.session.add(cal); db.session.commit()

    files = MediaFile.query.filter_by(user_id=current_user.id).order_by(MediaFile.created_at.desc()).all()
    ics_url = f"{url_for('calendar_ics', cal_id=cal.id, _external=True)}?token={cal.ics_token}"
    return render_template("dashboard.html", files=files, cal=cal, ics_url=ics_url)

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "password":
            old = request.form.get("old","")
            new = request.form.get("new","")
            if current_user.check_password(old) and new:
                current_user.set_password(new)
                db.session.commit()
                flash("Passwort geändert.", "success")
            else:
                flash("Fehler beim Passwortwechsel.", "error")
        elif action == "reset-2fa":
            secret = pyotp.random_base32()
            current_user.set_totp_secret(secret)
            current_user.is_totp_confirmed = False
            db.session.commit()
            flash("2FA zurückgesetzt. Bitte erneut einrichten.", "success")
    return render_template("profile.html")

# =============================================================================
# Upload / Download – BLOB in SQLite
# =============================================================================
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        abort(400, "no file field")
    f = request.files["file"]
    if f.filename == "":
        abort(400, "empty filename")
    safe_name = secure_filename(f.filename)
    if not allowed_file(safe_name):
        abort(400, "filetype not allowed")

    blob = f.read()
    if not blob:
        abort(400, "empty file")

    # Quota prüfen
    current = user_used_bytes(current_user.id)
    quota = (current_user.storage_quota_mb or 1024) * 1024 * 1024
    if current + len(blob) > quota:
        flash("Upload abgelehnt: Quota überschritten.", "error")
        return redirect(url_for("dashboard"))

    mt = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    digest = sha256_hex_of_bytes(blob)

    # Optional: Dedupe pro Nutzer
    existing = MediaFile.query.filter_by(user_id=current_user.id, sha256_hex=digest, size_bytes=len(blob)).first()
    if existing:
        mf = MediaFile(
            user_id=current_user.id, filename=safe_name, mimetype=mt,
            size_bytes=len(blob), sha256_hex=digest, data=existing.data
        )
    else:
        mf = MediaFile(
            user_id=current_user.id, filename=safe_name, mimetype=mt,
            size_bytes=len(blob), sha256_hex=digest, data=blob
        )

    db.session.add(mf)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/files/<int:file_id>")
@login_required
def download_file(file_id: int):
    mf = db.session.get(MediaFile, file_id)
    if not mf or mf.user_id != current_user.id:
        abort(404)

    def generate(data: bytes, chunk_size: int = 64 * 1024):
        mv = memoryview(data)
        for i in range(0, len(mv), chunk_size):
            yield mv[i:i+chunk_size]

    headers = {
        "Content-Type": mf.mimetype or "application/octet-stream",
        "Content-Length": str(mf.size_bytes),
        "Content-Disposition": f'attachment; filename="{mf.filename}"',
    }
    return Response(generate(mf.data), headers=headers, direct_passthrough=True)

# =============================================================================
# Events API (einfach)
# =============================================================================
@app.route("/api/events", methods=["GET", "POST"])
@login_required
def events_api():
    if request.method == "POST":
        data = request.get_json(force=True)
        cal = db.session.get(Calendar, int(data["calendar_id"]))
        if not cal or (cal.owner_id != current_user.id and current_user.role != "admin"):
            abort(403)
        starts = datetime.fromisoformat(data["starts_at"])
        ends = datetime.fromisoformat(data["ends_at"])
        if starts.tzinfo is None: starts = starts.replace(tzinfo=timezone.utc)
        if ends.tzinfo is None: ends = ends.replace(tzinfo=timezone.utc)
        ev = Event(calendar_id=cal.id,
                   title=data["title"].strip(),
                   starts_at=starts.astimezone(timezone.utc),
                   ends_at=ends.astimezone(timezone.utc),
                   all_day=bool(data.get("all_day", False)),
                   location=data.get("location"),
                   description=data.get("description"),
                   uid=secrets.token_urlsafe(16))
        db.session.add(ev); db.session.commit()
        return jsonify({"ok": True, "event_id": ev.id})

    cal_id = request.args.get("calendar_id", type=int)
    q = Event.query
    if cal_id: q = q.filter_by(calendar_id=cal_id)
    events = q.order_by(Event.starts_at.asc()).limit(200).all()
    return jsonify([{
        "id": e.id, "title": e.title,
        "starts_at": e.starts_at.isoformat(),
        "ends_at": e.ends_at.isoformat(),
        "all_day": e.all_day,
        "location": e.location,
        "description": e.description,
        "calendar_id": e.calendar_id
    } for e in events])

# =============================================================================
# ICS-API
# =============================================================================
@app.route("/api/calendar/<int:cal_id>.ics")
def calendar_ics(cal_id: int):
    token = request.args.get("token","")
    cal = db.session.get(Calendar, cal_id)
    if not cal or token != cal.ics_token:
        abort(403)

    ical = ICal()
    ical.add("prodid", "-//Intranet MVP//DE")
    ical.add("version", "2.0")

    for e in Event.query.filter_by(calendar_id=cal.id).order_by(Event.starts_at.asc()).all():
        ie = ICalEvent()
        ie.add("uid", e.uid or f"{e.id}@intranet.local")
        ie.add("summary", e.title)
        ie.add("dtstart", e.starts_at)
        ie.add("dtend", e.ends_at)
        if e.location: ie.add("location", e.location)
        if e.description: ie.add("description", e.description)
        ical.add_component(ie)

    payload = ical.to_ical()
    return Response(payload, mimetype="text/calendar; charset=utf-8")

@app.route("/api/calendar/<int:cal_id>/rotate_token", methods=["POST"])
@login_required
def rotate_token(cal_id: int):
    cal = db.session.get(Calendar, cal_id)
    if not cal or (cal.owner_id != current_user.id and current_user.role != "admin"):
        abort(403)
    cal.ics_token = secrets.token_hex(20)
    db.session.commit()
    flash("ICS-Token rotiert.", "success")
    return redirect(url_for("dashboard"))

# =============================================================================
# Admin-Panel
# =============================================================================
def require_admin():
    if not (current_user.is_authenticated and current_user.role == "admin"):
        abort(403)

@app.route("/admin")
@login_required
def admin_panel():
    require_admin()
    users = User.query.order_by(User.created_at.desc()).all()
    tokens = InviteToken.query.order_by(InviteToken.created_at.desc()).all()
    return render_template("admin.html", users=users, tokens=tokens)

@app.route("/admin/token", methods=["POST"])
@login_required
def generate_token():
    require_admin()
    role = request.form.get("role","user")
    uses = max(1, int(request.form.get("uses","1") or "1"))
    days = request.form.get("days","")
    expires = None
    if days:
        try:
            expires = now_utc() + timedelta(days=int(days))
        except Exception:
            expires = None

    code = secrets.token_urlsafe(18)
    token = InviteToken(
        code_hash=hash_token(code),
        role=role,
        uses_remaining=uses,
        purpose="invite",
        expires_at=expires,
        created_by_user_id=current_user.id
    )
    db.session.add(token); db.session.commit()
    link = f"{EXTERNAL_URL}/register?invite={code}&role={role}"
    qr_data_uri = qr_png_data_uri(link, box_size=6)  # Seite: Bild, kein ASCII
    return render_template("token_created.html", code=code, link=link, qr_data_uri=qr_data_uri)

@app.route("/admin/token/<int:token_id>/delete", methods=["POST"])
@login_required
def delete_token(token_id: int):
    require_admin()
    t = db.session.get(InviteToken, token_id)
    if t:
        db.session.delete(t); db.session.commit()
        flash("Token gelöscht.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@login_required
def set_role(user_id: int):
    require_admin()
    u = db.session.get(User, user_id)
    role = request.form.get("role","user")
    if u and role in ("user","admin"):
        u.role = role
        db.session.commit()
        flash("Rolle aktualisiert.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id: int):
    require_admin()
    if current_user.id == user_id:
        flash("Du kannst dich nicht selbst löschen.", "error")
        return redirect(url_for("admin_panel"))
    u = db.session.get(User, user_id)
    if u:
        db.session.delete(u); db.session.commit()
        flash("Nutzer gelöscht.", "success")
    return redirect(url_for("admin_panel"))

# =============================================================================
# App-Start
# =============================================================================
def init_db_and_bootstrap():
    db.create_all()
    ensure_bootstrap_token_and_print()

@app.cli.command("show-bootstrap")
def show_bootstrap():
    """Zeigt einen neuen Bootstrap-Link für die Admin-Erstregistrierung an (und erzeugt ihn)."""
    ensure_bootstrap_token_and_print()

if __name__ == "__main__":
    with app.app_context():
        init_db_and_bootstrap()
    app.run(debug=True)
