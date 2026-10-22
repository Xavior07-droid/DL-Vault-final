import hashlib
import json
import os
import re
import urllib.error
import urllib.request
import uuid
import secrets
import time
from functools import wraps

from dotenv import load_dotenv
from flask_wtf import CSRFProtect

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    abort,
    jsonify,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from datetime import datetime, timedelta

from models import (
    db,
    User,
    Asset,
    Nominee,
    WillInstruction,
    Document,
    DocumentProof,
    DigitalAccount,
    TrustedContact,
    LifeVerification,
    Task,
)

# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load variables from a local .env file if one exists (never committed —
# see .env.example for the template). In production, the real platform
# environment variables take precedence automatically.
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env_flag(name, default=False):
    """Read a boolean-ish environment variable ('1', 'true', 'yes')."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


IS_PRODUCTION = _env_flag("FLASK_ENV_PRODUCTION", default=False)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if IS_PRODUCTION:
        # Never fall back silently to a guessable key outside local dev.
        raise RuntimeError(
            "SECRET_KEY is not set. Create a .env file (see .env.example) "
            "or set SECRET_KEY in your hosting platform's environment "
            "variables before running in production."
        )
    # Local dev convenience only: generate a random key so the app still
    # runs without a .env file, but sessions will not persist across
    # restarts. Copy .env.example to .env and set a real value to avoid
    # this.
    SECRET_KEY = secrets.token_hex(32)
    print(
        "[dev warning] SECRET_KEY not set — using a random throwaway key "
        "for this run only. Copy .env.example to .env to fix this."
    )

DATABASE_PATH = os.environ.get(
    "DATABASE_PATH", os.path.join(BASE_DIR, "database", "legacy_vault.db")
)
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}
MAX_CONTENT_LENGTH = int(
    os.environ.get("MAX_UPLOAD_MB", "10")
) * 1024 * 1024  # default 10 MB per upload

# --- Blockchain notarization (optional) -----------------------------------
# Everything here is PUBLIC information. No private key or seed phrase is ever
# read, stored or needed: signing happens inside the user's own wallet.
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")

NOTARIZATION_CONTRACT_ADDRESS = (
    os.environ.get("NOTARIZATION_CONTRACT_ADDRESS", "").strip()
)
if not _ADDRESS_RE.fullmatch(NOTARIZATION_CONTRACT_ADDRESS):
    NOTARIZATION_CONTRACT_ADDRESS = ""  # unset or malformed -> feature is off

AMOY_CHAIN_ID = 80002
_rpc_url = os.environ.get("POLYGON_AMOY_RPC_URL", "").strip()
POLYGON_AMOY_RPC_URL = (
    _rpc_url if _rpc_url.startswith("https://") else "https://rpc-amoy.polygon.technology"
)
AMOY_EXPLORER = "https://amoy.polygonscan.com"
# ethers.js is served from this app's own static folder (see vendor_ethers.py)
# rather than a third-party CDN, so no outside code runs on the documents page.
ETHERS_LOCAL_PATH = os.path.join(BASE_DIR, "static", "vendor", "ethers.umd.min.js")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATABASE_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
# Cookies should only travel over HTTPS once actually deployed.
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Behind a host's HTTPS proxy (Render, Railway…) trust ONE proxy hop so the app
# sees the real client address and knows requests arrived over https.
if IS_PRODUCTION:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db.init_app(app)

# CSRF protection on every state-changing (POST/PUT/PATCH/DELETE) request.
# Every <form method="POST"> in templates/ must include {{ csrf_token() }}
# — csrf_token() is made available to Jinja automatically once this is
# initialized, no extra context processor needed.
csrf = CSRFProtect(app)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# The first bytes of a real file identify its true type, regardless of what
# it is named. Checking them stops e.g. an .exe renamed to "invoice.pdf".
_FILE_SIGNATURES = {
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
}


def content_matches_extension(file_storage, ext):
    """True if the upload's leading bytes match what its extension claims.

    Reads only the header and rewinds the stream so the file can still be
    saved afterwards.
    """
    signatures = _FILE_SIGNATURES.get(ext)
    if not signatures:
        return False
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    return any(header.startswith(sig) for sig in signatures)


def sha256_of_file(path):
    """SHA-256 fingerprint of a file on disk, as 64 lowercase hex characters.

    Read in chunks so a large upload never has to fit in memory. This is the
    ONLY thing about a notarized document that is ever made public: it proves
    the file has not changed, without revealing anything about its contents.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def notary_settings():
    """What the Documents page needs to know about notarization right now.

    Read at call time (not import time) so a missing vendor file or a changed
    setting is picked up without code changes.
    """
    contract_set = bool(NOTARIZATION_CONTRACT_ADDRESS)
    ethers_ready = os.path.isfile(ETHERS_LOCAL_PATH)
    return {
        "contract": NOTARIZATION_CONTRACT_ADDRESS,
        "contract_set": contract_set,
        "ethers_ready": ethers_ready,
        "enabled": contract_set and ethers_ready,
        "chain_id": AMOY_CHAIN_ID,
        "rpc_url": POLYGON_AMOY_RPC_URL,
        "explorer": AMOY_EXPLORER,
    }


def seal_document(document, filepath):
    """Integrity Seal: save the file's SHA-256 fingerprint and the time, privately.

    No wallet, no blockchain, no third party — the fingerprint stays in this
    vault's own database. If the file ever changes, it no longer matches and the
    Documents page shows "Tampered". (It protects against the FILE being
    altered; it is not an independent public timestamp like the blockchain.)
    """
    document.proof = DocumentProof(
        sha256_hash=sha256_of_file(filepath),
        ipfs_cid=None,
        network="local-seal",
        status="SEALED",
        notarized_at=datetime.utcnow(),
    )


def fetch_tx_receipt(tx_hash):
    """Ask the blockchain for a transaction's receipt (read-only, no keys).

    Returns the receipt dict, or None if the network does not know the
    transaction yet. Raises on network trouble.
    """
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "eth_getTransactionReceipt", "params": [tx_hash],
    }).encode()
    req = urllib.request.Request(
        POLYGON_AMOY_RPC_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
    if "error" in payload:
        raise RuntimeError(payload["error"].get("message", "RPC error"))
    return payload.get("result")


def check_notarization_receipt(receipt, contract_address, sha256_hex):
    """Decide whether a receipt really proves THIS fingerprint was registered.

    The browser tells us a transaction hash; we do not take its word for it.
    Returns (state, message, wallet) where state is one of:
      "ok"        the transaction succeeded, went to our contract, and its
                  DocumentRegistered event carries this exact fingerprint
      "pending"   the network has not mined it yet (try again shortly)
      "failed"    it was mined but reverted
      "mismatch"  it is a real transaction, but not a registration of this file
    """
    if not receipt:
        return "pending", "The blockchain hasn't confirmed that transaction yet.", None
    if receipt.get("status") != "0x1":
        return "failed", "That transaction failed on the blockchain.", None

    contract = contract_address.lower()
    if (receipt.get("to") or "").lower() != contract:
        return "mismatch", "That transaction wasn't sent to the notarization contract.", None

    wallet = receipt.get("from") or ""
    if not _ADDRESS_RE.fullmatch(wallet):
        return "mismatch", "That transaction has no valid sender.", None

    # DocumentRegistered(bytes32 indexed hash, ...) puts the fingerprint in
    # topics[1]. Requiring it ties the transaction to this exact document.
    expected = "0x" + sha256_hex.lower()
    for log in receipt.get("logs") or []:
        topics = log.get("topics") or []
        if (
            (log.get("address") or "").lower() == contract
            and len(topics) >= 2
            and str(topics[1]).lower() == expected
        ):
            return "ok", None, wallet
    return "mismatch", "That transaction doesn't record this document's fingerprint.", None


@app.errorhandler(413)
def upload_too_large(_error):
    """Friendly message instead of a bare '413 Request Entity Too Large'."""
    limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    flash(
        f"That file is too large. Please choose one under {limit_mb} MB.",
        "danger",
    )
    return redirect(url_for("document_upload"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Cheap, broadly safe browser protections on every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Pages with personal data must not be kept by shared caches or reused
    # from the back button after logging out.
    if "user_id" in session:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# --- Login throttling ------------------------------------------------------
# Slows down password guessing: 5 wrong attempts for the same email from the
# same address locks that pair for 15 minutes. Kept in memory (no extra
# service), so it is per server process and resets on restart — fine for a
# single-worker deployment, which is how this app is deployed.
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_FAILED_LOGINS = {}


def _login_key(email):
    return (request.remote_addr or "?", email)


def login_is_blocked(email):
    now = time.monotonic()
    key = _login_key(email)
    recent = [t for t in _FAILED_LOGINS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    if recent:
        _FAILED_LOGINS[key] = recent
    else:
        _FAILED_LOGINS.pop(key, None)
    return len(recent) >= LOGIN_MAX_FAILS


def record_failed_login(email):
    if len(_FAILED_LOGINS) > 5000:  # never let this grow without bound
        _FAILED_LOGINS.clear()
    _FAILED_LOGINS.setdefault(_login_key(email), []).append(time.monotonic())


MIN_PASSWORD_LENGTH = 8
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
MAX_ASSET_VALUE = 1_000_000_000_000


def parse_money(raw):
    """Turn a form value into a safe amount, or None if it isn't one.

    Blank means 0. Rejects text, NaN/infinity and negatives instead of
    crashing (a bare float() on user input is a 500 error waiting to happen).
    """
    raw = (raw or "").strip().replace(",", "")
    if not raw:
        return 0.0
    try:
        value = float(raw)
    except ValueError:
        return None
    if value != value or value < 0 or value > MAX_ASSET_VALUE:  # NaN, negative, absurd
        return None
    return value


def owned_asset_id(user, raw):
    """(ok, asset_id) for an asset id posted from a form.

    Blank is fine (instruction not tied to an asset). Anything else must be
    an asset that belongs to THIS user — never trust an id from the browser.
    """
    raw = (raw or "").strip()
    if not raw:
        return True, None
    if not raw.isdigit():
        return False, None
    asset = Asset.query.filter_by(id=int(raw), user_id=user.id).first()
    return (asset is not None), (asset.id if asset else None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


def compute_will_completeness(user):
    """
    Shared by the dashboard and the Will Checker so the same percentage
    means the same thing in both places. Runs the same four rules as
    will_checker() (asset has an instruction, instruction points to a
    real asset, asset has a nominee, instruction has a beneficiary) and
    returns {"percent": int, "pass_count": int, "total_count": int}.

    With nothing to check yet (no assets and no instructions), this is
    treated as 100% rather than 0% — an empty vault isn't "failing",
    it just hasn't been started.
    """
    assets = Asset.query.filter_by(user_id=user.id).all()
    instructions = WillInstruction.query.filter_by(user_id=user.id).all()

    if not assets and not instructions:
        return {"percent": 100, "pass_count": 0, "total_count": 0}

    checks = []
    for asset in assets:
        checks.append(any(i.asset_id == asset.id for i in instructions))
        checks.append(bool(asset.nominees))
    for instruction in instructions:
        checks.append(instruction.asset_id is None or instruction.asset is not None)
        checks.append(bool(instruction.beneficiary_name and instruction.beneficiary_name.strip()))

    pass_count = sum(1 for c in checks if c)
    total_count = len(checks)
    percent = round((pass_count / total_count) * 100) if total_count else 100
    return {"percent": percent, "pass_count": pass_count, "total_count": total_count}


# ---------------------------------------------------------------------------
# Home / Auth  (Step 1 & 2)
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password:
            flash("Please fill in every field so we can set up your vault.", "danger")
            return redirect(url_for("register"))

        if not _EMAIL_RE.fullmatch(email):
            flash("That email address doesn't look quite right.", "danger")
            return redirect(url_for("register"))

        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Please choose a password with at least {MIN_PASSWORD_LENGTH} characters.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Those two passwords don't match — please try again.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists. Try logging in instead.", "danger")
            return redirect(url_for("register"))

        user = User(full_name=full_name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Your vault is ready. Please log in to begin.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if login_is_blocked(email):
            flash("Too many tries. Please wait a few minutes before logging in again.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            _FAILED_LOGINS.pop(_login_key(email), None)
            # Keep the CSRF token that Flask-WTF stored for this very
            # login form; session.clear() would wipe it and can cause a
            # "CSRF session token is missing" error on the very next
            # POST if any code path re-renders a page against the old
            # token before a new one is issued.
            csrf_token_value = session.get("csrf_token")
            session.clear()
            if csrf_token_value is not None:
                session["csrf_token"] = csrf_token_value
            session["user_id"] = user.id
            session["full_name"] = user.full_name
            flash(f"Welcome back, {user.full_name}!", "success")
            return redirect(url_for("dashboard"))

        record_failed_login(email)
        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You're logged out. Take care.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard (Step 3)
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    stats = {
        "assets": Asset.query.filter_by(user_id=user.id).count(),
        "nominees": Nominee.query.filter_by(user_id=user.id).count(),
        "documents": Document.query.filter_by(user_id=user.id).count(),
        "will_instructions": WillInstruction.query.filter_by(user_id=user.id).count(),
        "digital_accounts": DigitalAccount.query.filter_by(user_id=user.id).count(),
        "tasks": Task.query.filter_by(user_id=user.id).count(),
        "tasks_pending": Task.query.filter_by(user_id=user.id)
            .filter(Task.status != "Completed").count(),
    }
    will_completeness = compute_will_completeness(user)
    verification = get_or_create_verification(user)
    if verification.next_verification_due < datetime.utcnow() and verification.status == "OK":
        verification.status = "VERIFICATION_REQUIRED"
        db.session.commit()
    return render_template(
        "dashboard.html",
        stats=stats,
        verification=verification,
        will_completeness=will_completeness,
    )


# ---------------------------------------------------------------------------
# Asset Management (Step 4)
# ---------------------------------------------------------------------------
@app.route("/assets")
@login_required
def assets_list():
    user = current_user()
    assets = Asset.query.filter_by(user_id=user.id).order_by(Asset.created_at.desc()).all()
    return render_template("assets.html", assets=assets)


@app.route("/assets/add", methods=["GET", "POST"])
@login_required
def asset_add():
    if request.method == "POST":
        user = current_user()
        value = parse_money(request.form.get("approx_value"))
        if value is None:
            flash("Please enter the approximate value as a plain number, like 25000.", "danger")
            return redirect(url_for("asset_add"))
        asset = Asset(
            user_id=user.id,
            name=request.form.get("name", "").strip(),
            category=request.form.get("category", "").strip(),
            provider=request.form.get("provider", "").strip(),
            reference=request.form.get("reference", "").strip(),
            approx_value=value,
            description=request.form.get("description", "").strip(),
        )

        if not asset.name or not asset.category:
            flash("Please give your asset a name and a category.", "danger")
            return redirect(url_for("asset_add"))

        db.session.add(asset)
        db.session.commit()
        flash("Asset added to your vault.", "success")
        return redirect(url_for("assets_list"))

    return render_template("asset_form.html", asset=None)


@app.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@login_required
def asset_edit(asset_id):
    user = current_user()
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first_or_404()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        value = parse_money(request.form.get("approx_value"))
        if not name or not category:
            flash("Please give your asset a name and a category.", "danger")
            return redirect(url_for("asset_edit", asset_id=asset.id))
        if value is None:
            flash("Please enter the approximate value as a plain number, like 25000.", "danger")
            return redirect(url_for("asset_edit", asset_id=asset.id))
        asset.name = name
        asset.category = category
        asset.provider = request.form.get("provider", "").strip()
        asset.reference = request.form.get("reference", "").strip()
        asset.approx_value = value
        asset.description = request.form.get("description", "").strip()

        db.session.commit()
        flash("Asset updated.", "success")
        return redirect(url_for("assets_list"))

    return render_template("asset_form.html", asset=asset)


@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def asset_delete(asset_id):
    user = current_user()
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first_or_404()
    db.session.delete(asset)
    db.session.commit()
    flash("Asset deleted.", "info")
    return redirect(url_for("assets_list"))


# ---------------------------------------------------------------------------
# Nominee Management (Step 5)
# ---------------------------------------------------------------------------
@app.route("/nominees")
@login_required
def nominees_list():
    user = current_user()
    nominees = (
        Nominee.query.filter_by(user_id=user.id).order_by(Nominee.created_at.desc()).all()
    )
    return render_template("nominees.html", nominees=nominees)


@app.route("/nominees/add", methods=["GET", "POST"])
@login_required
def nominee_add():
    if request.method == "POST":
        user = current_user()
        nominee = Nominee(
            user_id=user.id,
            name=request.form.get("name", "").strip(),
            relationship_=request.form.get("relationship", "").strip(),
            email=request.form.get("email", "").strip(),
            phone=request.form.get("phone", "").strip(),
        )

        if not nominee.name or not nominee.relationship_:
            flash("Please add the nominee's name and their relationship to you.", "danger")
            return redirect(url_for("nominee_add"))

        db.session.add(nominee)
        db.session.commit()
        flash("Nominee added.", "success")
        return redirect(url_for("nominees_list"))

    return render_template("nominee_form.html", nominee=None)


@app.route("/nominees/<int:nominee_id>/edit", methods=["GET", "POST"])
@login_required
def nominee_edit(nominee_id):
    user = current_user()
    nominee = Nominee.query.filter_by(id=nominee_id, user_id=user.id).first_or_404()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        relationship = request.form.get("relationship", "").strip()
        if not name or not relationship:
            flash("Please add the nominee's name and their relationship to you.", "danger")
            return redirect(url_for("nominee_edit", nominee_id=nominee.id))
        nominee.name = name
        nominee.relationship_ = relationship
        nominee.email = request.form.get("email", "").strip()
        nominee.phone = request.form.get("phone", "").strip()

        db.session.commit()
        flash("Nominee updated.", "success")
        return redirect(url_for("nominees_list"))

    return render_template("nominee_form.html", nominee=nominee)


@app.route("/nominees/<int:nominee_id>/delete", methods=["POST"])
@login_required
def nominee_delete(nominee_id):
    user = current_user()
    nominee = Nominee.query.filter_by(id=nominee_id, user_id=user.id).first_or_404()
    db.session.delete(nominee)
    db.session.commit()
    flash("Nominee deleted.", "info")
    return redirect(url_for("nominees_list"))


@app.route("/assets/<int:asset_id>/assign-nominee", methods=["GET", "POST"])
@login_required
def assign_nominee(asset_id):
    user = current_user()
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first_or_404()
    all_nominees = Nominee.query.filter_by(user_id=user.id).all()

    if request.method == "POST":
        nominee_id = request.form.get("nominee_id")
        nominee = Nominee.query.filter_by(id=nominee_id, user_id=user.id).first()

        if not nominee:
            flash("Please choose a nominee from the list.", "danger")
        elif nominee in asset.nominees:
            flash("That nominee is already looking after this asset.", "warning")
        else:
            asset.nominees.append(nominee)
            db.session.commit()
            flash(f"{nominee.name} assigned to {asset.name}.", "success")

        return redirect(url_for("assign_nominee", asset_id=asset.id))

    return render_template("assign_nominee.html", asset=asset, all_nominees=all_nominees)


@app.route("/assets/<int:asset_id>/remove-nominee/<int:nominee_id>", methods=["POST"])
@login_required
def remove_nominee(asset_id, nominee_id):
    user = current_user()
    asset = Asset.query.filter_by(id=asset_id, user_id=user.id).first_or_404()
    nominee = Nominee.query.filter_by(id=nominee_id, user_id=user.id).first_or_404()

    if nominee in asset.nominees:
        asset.nominees.remove(nominee)
        db.session.commit()
        flash(f"{nominee.name} removed from {asset.name}.", "info")

    return redirect(url_for("assign_nominee", asset_id=asset.id))


# ---------------------------------------------------------------------------
# Will / Inheritance Instructions (Step 6)
# ---------------------------------------------------------------------------
@app.route("/will")
@login_required
def will_list():
    user = current_user()
    instructions = (
        WillInstruction.query.filter_by(user_id=user.id)
        .order_by(WillInstruction.created_at.desc())
        .all()
    )
    return render_template("will.html", instructions=instructions)


@app.route("/will/add", methods=["GET", "POST"])
@login_required
def will_add():
    user = current_user()
    user_assets = Asset.query.filter_by(user_id=user.id).all()

    if request.method == "POST":
        asset_ok, asset_id = owned_asset_id(user, request.form.get("asset_id"))
        beneficiary_name = request.form.get("beneficiary_name", "").strip()
        instruction_text = request.form.get("instruction_text", "").strip()

        if not asset_ok:
            flash("Please choose one of your own assets from the list.", "danger")
            return redirect(url_for("will_add"))

        if not beneficiary_name or not instruction_text:
            flash("Please say who this is for and write the instruction.", "danger")
            return redirect(url_for("will_add"))

        instruction = WillInstruction(
            user_id=user.id,
            asset_id=asset_id,
            beneficiary_name=beneficiary_name,
            instruction_text=instruction_text,
        )
        db.session.add(instruction)
        db.session.commit()
        flash("Instruction added to your will.", "success")
        return redirect(url_for("will_list"))

    return render_template("will_form.html", instruction=None, user_assets=user_assets)


@app.route("/will/<int:instruction_id>/edit", methods=["GET", "POST"])
@login_required
def will_edit(instruction_id):
    user = current_user()
    instruction = WillInstruction.query.filter_by(
        id=instruction_id, user_id=user.id
    ).first_or_404()
    user_assets = Asset.query.filter_by(user_id=user.id).all()

    if request.method == "POST":
        asset_ok, asset_id = owned_asset_id(user, request.form.get("asset_id"))
        beneficiary_name = request.form.get("beneficiary_name", "").strip()
        instruction_text = request.form.get("instruction_text", "").strip()

        if not asset_ok:
            flash("Please choose one of your own assets from the list.", "danger")
            return redirect(url_for("will_edit", instruction_id=instruction.id))
        # A blank beneficiary is allowed on edit ON PURPOSE: the Will Checker's
        # "instruction has a beneficiary" rule exists to flag exactly that.
        if not instruction_text:
            flash("Please write the instruction itself.", "danger")
            return redirect(url_for("will_edit", instruction_id=instruction.id))

        instruction.asset_id = asset_id
        instruction.beneficiary_name = beneficiary_name
        instruction.instruction_text = instruction_text

        db.session.commit()
        flash("Instruction updated.", "success")
        return redirect(url_for("will_list"))

    return render_template("will_form.html", instruction=instruction, user_assets=user_assets)


@app.route("/will/<int:instruction_id>/delete", methods=["POST"])
@login_required
def will_delete(instruction_id):
    user = current_user()
    instruction = WillInstruction.query.filter_by(
        id=instruction_id, user_id=user.id
    ).first_or_404()
    db.session.delete(instruction)
    db.session.commit()
    flash("Will instruction deleted.", "info")
    return redirect(url_for("will_list"))


# ---------------------------------------------------------------------------
# Will Checker (Step 7) — simple rule-based checks, no AI
# ---------------------------------------------------------------------------
@app.route("/will/checker")
@login_required
def will_checker():
    user = current_user()

    assets = Asset.query.filter_by(user_id=user.id).all()
    instructions = WillInstruction.query.filter_by(user_id=user.id).all()

    results = []

    # Rule 1: Asset without any will instruction
    for asset in assets:
        has_instruction = any(i.asset_id == asset.id for i in instructions)
        if has_instruction:
            results.append({
                "rule": "Asset has a will instruction",
                "subject": asset.name,
                "status": "PASS",
                "detail": f'"{asset.name}" is covered by a will instruction.',
            })
        else:
            results.append({
                "rule": "Asset has a will instruction",
                "subject": asset.name,
                "status": "WARNING",
                "detail": f'"{asset.name}" has no will instruction yet — worth adding one.',
            })

    # Rule 2: Will instruction pointing to a missing/deleted asset
    for instruction in instructions:
        if instruction.asset_id is not None and instruction.asset is None:
            results.append({
                "rule": "Instruction refers to an existing asset",
                "subject": instruction.beneficiary_name,
                "status": "WARNING",
                "detail": (
                    f'Instruction for "{instruction.beneficiary_name}" refers to '
                    "an asset that no longer exists."
                ),
            })
        else:
            results.append({
                "rule": "Instruction refers to an existing asset",
                "subject": instruction.beneficiary_name,
                "status": "PASS",
                "detail": (
                    f'Instruction for "{instruction.beneficiary_name}" refers to '
                    f'"{instruction.asset.name}".'
                    if instruction.asset
                    else f'Instruction for "{instruction.beneficiary_name}" is not tied to a specific asset.'
                ),
            })

    # Rule 3: Asset without any nominee assigned
    for asset in assets:
        if asset.nominees:
            results.append({
                "rule": "Asset has a nominee",
                "subject": asset.name,
                "status": "PASS",
                "detail": f'"{asset.name}" has at least one nominee assigned.',
            })
        else:
            results.append({
                "rule": "Asset has a nominee",
                "subject": asset.name,
                "status": "WARNING",
                "detail": f'"{asset.name}" has no nominee yet — consider assigning someone.',
            })

    # Rule 4: Will instruction without a beneficiary
    for instruction in instructions:
        if instruction.beneficiary_name and instruction.beneficiary_name.strip():
            results.append({
                "rule": "Instruction has a beneficiary",
                "subject": instruction.instruction_text[:40],
                "status": "PASS",
                "detail": f'Instruction is assigned to beneficiary "{instruction.beneficiary_name}".',
            })
        else:
            results.append({
                "rule": "Instruction has a beneficiary",
                "subject": instruction.instruction_text[:40],
                "status": "WARNING",
                "detail": "Instruction has no beneficiary specified.",
            })

    warning_count = sum(1 for r in results if r["status"] == "WARNING")
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    completeness = compute_will_completeness(user)

    return render_template(
        "will_checker.html",
        results=results,
        warning_count=warning_count,
        pass_count=pass_count,
        completeness=completeness,
        has_data=bool(assets or instructions),
    )


# ---------------------------------------------------------------------------
# Document Management (Step 8)
# ---------------------------------------------------------------------------
DOCUMENT_CATEGORIES = [
    "Identity Proof",
    "Property Papers",
    "Insurance",
    "Bank Statement",
    "Investment",
    "Will",
    "Other",
]


@app.route("/documents")
@login_required
def documents_list():
    user = current_user()
    documents = (
        Document.query.filter_by(user_id=user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    # Quick local integrity check for notarized documents: does the stored file
    # still match the fingerprint saved when it was notarized? (The blockchain
    # comparison itself happens when the person presses Verify.)
    integrity = {}
    for doc in documents:
        if doc.proof and doc.proof.status in ("NOTARIZED", "SEALED"):
            path = os.path.join(UPLOAD_DIR, doc.stored_filename)
            if not os.path.isfile(path):
                integrity[doc.id] = "missing"
            elif sha256_of_file(path) != doc.proof.sha256_hash:
                integrity[doc.id] = "changed"
    return render_template(
        "documents.html", documents=documents, notary=notary_settings(),
        integrity=integrity,
    )


@app.route("/documents/upload", methods=["GET", "POST"])
@login_required
def document_upload():
    if request.method == "POST":
        user = current_user()

        file = request.files.get("file")
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        # Notarization is strictly opt-in, per document. Anything other than
        # the checkbox being ticked means "no".
        notarize = request.form.get("notarize") == "on"
        seal = request.form.get("seal") == "on" and not notarize

        if category not in DOCUMENT_CATEGORIES:
            flash("Please choose a category from the list.", "danger")
            return redirect(url_for("document_upload"))

        if not file or file.filename == "":
            flash("Please choose a file to upload.", "danger")
            return redirect(url_for("document_upload"))

        if not allowed_file(file.filename):
            flash("Sorry, we can only store PDF, JPG, JPEG and PNG files.", "danger")
            return redirect(url_for("document_upload"))

        original_filename = secure_filename(file.filename)
        # secure_filename can strip a name down to nothing useful (e.g. a
        # filename made only of special characters), so re-validate it.
        if not original_filename or not allowed_file(original_filename):
            flash("Sorry, we can only store PDF, JPG, JPEG and PNG files.", "danger")
            return redirect(url_for("document_upload"))
        ext = original_filename.rsplit(".", 1)[1].lower()

        if not content_matches_extension(file, ext):
            flash(
                "That file doesn't look like a real "
                f"{ext.upper()} — its contents don't match its name.",
                "danger",
            )
            return redirect(url_for("document_upload"))

        stored_filename = f"{uuid.uuid4().hex}.{ext}"

        filepath = os.path.join(UPLOAD_DIR, stored_filename)
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        document = Document(
            user_id=user.id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            category=category,
            description=description,
            file_size=file_size,
        )
        db.session.add(document)

        if notarize:
            # Fingerprint only: the file stays in the vault and is never sent
            # anywhere. ipfs_cid stays empty on purpose (no public upload).
            # PENDING = fingerprint saved, not yet recorded on the blockchain.
            document.proof = DocumentProof(
                sha256_hash=sha256_of_file(filepath),
                ipfs_cid=None,
                status="PENDING",
            )

        if seal:
            seal_document(document, filepath)

        db.session.commit()

        if seal:
            flash("Document safely filed away and sealed. If the file ever changes, you'll be told.", "success")
        elif notarize:
            flash(
                "Document uploaded. Its fingerprint is saved and ready to be "
                "notarized — the file itself stays private.",
                "success",
            )
        else:
            flash("Document safely filed away.", "success")
        return redirect(url_for("documents_list"))

    return render_template(
        "document_upload.html",
        categories=DOCUMENT_CATEGORIES,
        max_mb=app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
        notary=notary_settings(),
    )


@app.route("/documents/<int:document_id>/seal", methods=["POST"])
@login_required
def document_seal(document_id):
    """Add an Integrity Seal to a document that has none yet."""
    user = current_user()
    document = Document.query.filter_by(id=document_id, user_id=user.id).first_or_404()
    if document.proof:
        flash("This document already has a fingerprint saved.", "info")
        return redirect(url_for("documents_list"))
    path = os.path.join(UPLOAD_DIR, document.stored_filename)
    if not os.path.isfile(path):
        flash("We couldn't find the stored file, so it can't be sealed.", "danger")
        return redirect(url_for("documents_list"))
    seal_document(document, path)
    db.session.commit()
    flash("Sealed. If this file ever changes, you'll be told.", "success")
    return redirect(url_for("documents_list"))


@app.route("/documents/<int:document_id>/fingerprint")
@login_required
def document_fingerprint(document_id):
    """Re-hash the stored file RIGHT NOW and report it next to the saved one.

    The Verify control compares these two (and the blockchain record) in the
    browser. Scoped to the logged-in user like every other document route.
    """
    user = current_user()
    document = Document.query.filter_by(id=document_id, user_id=user.id).first_or_404()
    path = os.path.join(UPLOAD_DIR, document.stored_filename)
    if not os.path.isfile(path):
        return jsonify(ok=False, error="The stored file could not be found."), 404
    proof = document.proof
    return jsonify(
        ok=True,
        current_hash=sha256_of_file(path),
        stored_hash=proof.sha256_hash if proof else None,
        status=proof.status if proof else None,
        tx_hash=proof.tx_hash if proof else None,
        wallet_address=proof.wallet_address if proof else None,
    )


@app.route("/documents/<int:document_id>/notarize/confirm", methods=["POST"])
@login_required
def document_notarize_confirm(document_id):
    """Record that the browser's transaction really notarized this document.

    The browser sends only a transaction hash. We fetch the receipt from the
    blockchain ourselves and check it, so a document is never marked
    NOTARIZED on the browser's say-so. CSRF-protected (X-CSRFToken header).
    """
    if not NOTARIZATION_CONTRACT_ADDRESS:
        return jsonify(ok=False, error="Notarization isn't switched on yet."), 400

    user = current_user()
    document = Document.query.filter_by(id=document_id, user_id=user.id).first_or_404()
    proof = document.proof
    if proof is None:
        return jsonify(ok=False, error="This document wasn't set up for notarization."), 400
    if proof.status == "NOTARIZED":
        return jsonify(ok=True, already=True, tx_hash=proof.tx_hash)

    data = request.get_json(silent=True) or {}
    tx_hash = str(data.get("tx_hash", "")).strip()
    if not _TX_HASH_RE.fullmatch(tx_hash):
        return jsonify(ok=False, error="That doesn't look like a transaction hash."), 400

    # The fingerprint we are about to vouch for must still describe the file.
    path = os.path.join(UPLOAD_DIR, document.stored_filename)
    if not os.path.isfile(path) or sha256_of_file(path) != proof.sha256_hash:
        return jsonify(
            ok=False,
            error="This file has changed since its fingerprint was saved.",
        ), 409

    try:
        receipt = fetch_tx_receipt(tx_hash)
    except (urllib.error.URLError, OSError, RuntimeError, ValueError):
        return jsonify(
            ok=False,
            error="Couldn't reach the blockchain to confirm. Please try again in a moment.",
        ), 502

    state, message, wallet = check_notarization_receipt(
        receipt, NOTARIZATION_CONTRACT_ADDRESS, proof.sha256_hash
    )
    if state == "pending":
        return jsonify(ok=False, pending=True, error=message), 202
    if state == "failed":
        proof.status = "FAILED"
        proof.tx_hash = tx_hash
        db.session.commit()
        return jsonify(ok=False, error=message), 400
    if state != "ok":
        return jsonify(ok=False, error=message), 400

    proof.status = "NOTARIZED"
    proof.tx_hash = tx_hash
    proof.wallet_address = wallet  # taken from the receipt, not from the browser
    proof.network = "polygon-amoy-testnet"
    proof.notarized_at = datetime.utcnow()
    db.session.commit()
    return jsonify(ok=True, tx_hash=tx_hash)


@app.route("/documents/<int:document_id>/download")
@login_required
def document_download(document_id):
    user = current_user()
    document = Document.query.filter_by(id=document_id, user_id=user.id).first_or_404()
    return send_from_directory(
        UPLOAD_DIR, document.stored_filename, as_attachment=True,
        download_name=document.original_filename,
    )


@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def document_delete(document_id):
    user = current_user()
    document = Document.query.filter_by(id=document_id, user_id=user.id).first_or_404()

    filepath = os.path.join(UPLOAD_DIR, document.stored_filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    db.session.delete(document)
    db.session.commit()
    flash("Document deleted.", "info")
    return redirect(url_for("documents_list"))


# ---------------------------------------------------------------------------
# Digital Legacy — digital accounts (Step 9)
# ---------------------------------------------------------------------------
DIGITAL_ACCOUNT_ACTIONS = ["Preserve", "Memorialize", "Transfer", "Delete"]


@app.route("/digital-legacy")
@login_required
def digital_accounts_list():
    user = current_user()
    accounts = (
        DigitalAccount.query.filter_by(user_id=user.id)
        .order_by(DigitalAccount.created_at.desc())
        .all()
    )
    return render_template("digital_legacy.html", accounts=accounts)


@app.route("/digital-legacy/add", methods=["GET", "POST"])
@login_required
def digital_account_add():
    if request.method == "POST":
        user = current_user()
        account = DigitalAccount(
            user_id=user.id,
            service=request.form.get("service", "").strip(),
            account_identifier=request.form.get("account_identifier", "").strip(),
            action=request.form.get("action", "").strip(),
            beneficiary=request.form.get("beneficiary", "").strip(),
            instructions=request.form.get("instructions", "").strip(),
        )

        if (not account.service or not account.account_identifier
                or account.action not in DIGITAL_ACCOUNT_ACTIONS):
            flash("Please add the service, the account name, and what should happen to it.", "danger")
            return redirect(url_for("digital_account_add"))

        db.session.add(account)
        db.session.commit()
        flash("Account added.", "success")
        return redirect(url_for("digital_accounts_list"))

    return render_template(
        "digital_legacy_form.html", account=None, actions=DIGITAL_ACCOUNT_ACTIONS
    )


@app.route("/digital-legacy/<int:account_id>/edit", methods=["GET", "POST"])
@login_required
def digital_account_edit(account_id):
    user = current_user()
    account = DigitalAccount.query.filter_by(
        id=account_id, user_id=user.id
    ).first_or_404()

    if request.method == "POST":
        service = request.form.get("service", "").strip()
        identifier = request.form.get("account_identifier", "").strip()
        action = request.form.get("action", "").strip()
        if not service or not identifier or action not in DIGITAL_ACCOUNT_ACTIONS:
            flash("Please add the service, the account name, and what should happen to it.", "danger")
            return redirect(url_for("digital_account_edit", account_id=account.id))
        account.service = service
        account.account_identifier = identifier
        account.action = action
        account.beneficiary = request.form.get("beneficiary", "").strip()
        account.instructions = request.form.get("instructions", "").strip()

        db.session.commit()
        flash("Account updated.", "success")
        return redirect(url_for("digital_accounts_list"))

    return render_template(
        "digital_legacy_form.html", account=account, actions=DIGITAL_ACCOUNT_ACTIONS
    )


@app.route("/digital-legacy/<int:account_id>/delete", methods=["POST"])
@login_required
def digital_account_delete(account_id):
    user = current_user()
    account = DigitalAccount.query.filter_by(
        id=account_id, user_id=user.id
    ).first_or_404()
    db.session.delete(account)
    db.session.commit()
    flash("Digital account deleted.", "info")
    return redirect(url_for("digital_accounts_list"))


# ---------------------------------------------------------------------------
# Trusted Contact (Step 10)
# ---------------------------------------------------------------------------
@app.route("/trusted-contacts")
@login_required
def trusted_contacts_list():
    user = current_user()
    contacts = (
        TrustedContact.query.filter_by(user_id=user.id)
        .order_by(TrustedContact.created_at.desc())
        .all()
    )
    return render_template("trusted_contacts.html", contacts=contacts)


@app.route("/trusted-contacts/add", methods=["GET", "POST"])
@login_required
def trusted_contact_add():
    if request.method == "POST":
        user = current_user()
        contact = TrustedContact(
            user_id=user.id,
            name=request.form.get("name", "").strip(),
            relationship_=request.form.get("relationship", "").strip(),
            email=request.form.get("email", "").strip(),
            phone=request.form.get("phone", "").strip(),
        )

        if not contact.name or not contact.relationship_:
            flash("Please add a name and how they're connected to you.", "danger")
            return redirect(url_for("trusted_contact_add"))

        db.session.add(contact)
        db.session.commit()
        flash("Trusted contact added.", "success")
        return redirect(url_for("trusted_contacts_list"))

    return render_template("trusted_contact_form.html", contact=None)


@app.route("/trusted-contacts/<int:contact_id>/edit", methods=["GET", "POST"])
@login_required
def trusted_contact_edit(contact_id):
    user = current_user()
    contact = TrustedContact.query.filter_by(
        id=contact_id, user_id=user.id
    ).first_or_404()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        relationship = request.form.get("relationship", "").strip()
        if not name or not relationship:
            flash("Please add a name and how they're connected to you.", "danger")
            return redirect(url_for("trusted_contact_edit", contact_id=contact.id))
        contact.name = name
        contact.relationship_ = relationship
        contact.email = request.form.get("email", "").strip()
        contact.phone = request.form.get("phone", "").strip()

        db.session.commit()
        flash("Trusted contact updated.", "success")
        return redirect(url_for("trusted_contacts_list"))

    return render_template("trusted_contact_form.html", contact=contact)


@app.route("/trusted-contacts/<int:contact_id>/delete", methods=["POST"])
@login_required
def trusted_contact_delete(contact_id):
    user = current_user()
    contact = TrustedContact.query.filter_by(
        id=contact_id, user_id=user.id
    ).first_or_404()
    db.session.delete(contact)
    db.session.commit()
    flash("Trusted contact deleted.", "info")
    return redirect(url_for("trusted_contacts_list"))


# ---------------------------------------------------------------------------
# Life Verification (Step 11) — SIMULATION ONLY
#
# This module never releases anything automatically. It only tracks a
# last/next check-in date and a status flag. A missed verification just
# flips the status to VERIFICATION_REQUIRED for the user to see.
# ---------------------------------------------------------------------------
def get_or_create_verification(user):
    record = LifeVerification.query.filter_by(user_id=user.id).first()
    if not record:
        now = datetime.utcnow()
        record = LifeVerification(
            user_id=user.id,
            last_verified_at=now,
            next_verification_due=now + timedelta(days=30),
            status="OK",
            verification_interval_days=30,
        )
        db.session.add(record)
        db.session.commit()
    return record


@app.route("/life-verification")
@login_required
def life_verification():
    user = current_user()
    record = get_or_create_verification(user)

    # If the due date has quietly passed (e.g. app reopened later),
    # reflect that in the status without doing anything else.
    if record.next_verification_due < datetime.utcnow() and record.status == "OK":
        record.status = "VERIFICATION_REQUIRED"
        db.session.commit()

    # Whole days until the next check-in is due (negative = overdue). Worked
    # out here so the template can speak in plain language ("12 days from
    # now") rather than showing raw dates alone.
    seconds_left = (record.next_verification_due - datetime.utcnow()).total_seconds()
    # int() truncates toward zero, so 1.5 days overdue reads "1 day ago", not 2.
    days_left = int(seconds_left / 86400)

    return render_template(
        "life_verification.html", record=record, days_left=days_left
    )


@app.route("/life-verification/confirm", methods=["POST"])
@login_required
def life_verification_confirm():
    user = current_user()
    record = get_or_create_verification(user)

    now = datetime.utcnow()
    record.last_verified_at = now
    record.next_verification_due = now + timedelta(days=record.verification_interval_days)
    record.status = "OK"
    db.session.commit()

    flash("Thank you — you're checked in. Your next check-in date has been reset.", "success")
    return redirect(url_for("life_verification"))


@app.route("/life-verification/simulate-missed", methods=["POST"])
@login_required
def life_verification_simulate_missed():
    """Development/demo only: pretend the check-in window passed."""
    user = current_user()
    record = get_or_create_verification(user)

    record.next_verification_due = datetime.utcnow() - timedelta(days=1)
    record.status = "VERIFICATION_REQUIRED"
    db.session.commit()

    flash(
        "Demo only: we've pretended a check-in was missed so you can see how "
        "it looks. Nothing has been shared or changed.",
        "warning",
    )
    return redirect(url_for("life_verification"))


# ---------------------------------------------------------------------------
# Inheritance Tasks (Step 12)
# ---------------------------------------------------------------------------
TASK_STATUSES = ["Pending", "In Progress", "Completed"]


@app.route("/tasks")
@login_required
def tasks_list():
    user = current_user()
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.created_at.desc()).all()

    # Progress overview, counted from this user's own tasks only.
    counts = {s: 0 for s in TASK_STATUSES}
    for t in tasks:
        if t.status in counts:
            counts[t.status] += 1
    total = len(tasks)
    percent_done = round(counts["Completed"] * 100 / total) if total else 0

    return render_template(
        "tasks.html",
        tasks=tasks,
        statuses=TASK_STATUSES,
        counts=counts,
        total=total,
        percent_done=percent_done,
    )


@app.route("/tasks/add", methods=["GET", "POST"])
@login_required
def task_add():
    if request.method == "POST":
        user = current_user()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        status = request.form.get("status", "Pending").strip()

        if not title:
            flash("Please give the task a title.", "danger")
            return redirect(url_for("task_add"))

        if status not in TASK_STATUSES:
            status = "Pending"

        task = Task(
            user_id=user.id,
            title=title,
            description=description,
            status=status,
        )
        db.session.add(task)
        db.session.commit()
        flash("Task added.", "success")
        return redirect(url_for("tasks_list"))

    return render_template("task_form.html", task=None, statuses=TASK_STATUSES)


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def task_edit(task_id):
    user = current_user()
    task = Task.query.filter_by(id=task_id, user_id=user.id).first_or_404()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        status = request.form.get("status", "Pending").strip()

        if not title:
            flash("Please give the task a title.", "danger")
            return redirect(url_for("task_edit", task_id=task.id))

        task.title = title
        task.description = request.form.get("description", "").strip()
        # An unrecognised status (only possible from a hand-made request) keeps
        # whatever the task already had, rather than silently resetting it.
        if status in TASK_STATUSES:
            task.status = status

        db.session.commit()
        flash("Task updated.", "success")
        return redirect(url_for("tasks_list"))

    return render_template("task_form.html", task=task, statuses=TASK_STATUSES)


@app.route("/tasks/<int:task_id>/status", methods=["POST"])
@login_required
def task_update_status(task_id):
    """Quick status change from the task list (no full edit form)."""
    user = current_user()
    task = Task.query.filter_by(id=task_id, user_id=user.id).first_or_404()

    new_status = request.form.get("status", "").strip()
    if new_status in TASK_STATUSES:
        task.status = new_status
        db.session.commit()
        flash(f'Task "{task.title}" marked as {new_status}.', "success")
    else:
        flash("That isn't a status we recognise.", "danger")

    return redirect(url_for("tasks_list"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def task_delete(task_id):
    user = current_user()
    task = Task.query.filter_by(id=task_id, user_id=user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "info")
    return redirect(url_for("tasks_list"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
with app.app_context():
    db.create_all()


@app.route("/healthz")
def healthz():
    """Plain 'ok' for the hosting platform's health check. No data, no login."""
    return "ok", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    # Debug mode is for local development only — never on a real deployment.
    app.run(debug=not IS_PRODUCTION)
