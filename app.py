import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.request
import uuid
import secrets
import time
from functools import wraps

import qrcode
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image as RLImage,
    KeepTogether,
    HRFlowable,
)

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
    send_file,
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
app.config["SESSION_COOKIE_NAME"] = "__session"

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
    assets = Asset.query.filter_by(user_id=user.id).all()
    total_estate_value = sum(a.approx_value or 0 for a in assets)
    
    # Asset category breakdown for visual charts
    category_totals = {}
    for a in assets:
        cat = a.category or "Other"
        category_totals[cat] = category_totals.get(cat, 0.0) + (a.approx_value or 0.0)

    # Sort categories by value
    sorted_categories = sorted(category_totals.items(), key=lambda x: x[1], reverse=True)

    stats = {
        "assets": len(assets),
        "nominees": Nominee.query.filter_by(user_id=user.id).count(),
        "documents": Document.query.filter_by(user_id=user.id).count(),
        "will_instructions": WillInstruction.query.filter_by(user_id=user.id).count(),
        "digital_accounts": DigitalAccount.query.filter_by(user_id=user.id).count(),
        "tasks": Task.query.filter_by(user_id=user.id).count(),
        "tasks_pending": Task.query.filter_by(user_id=user.id)
            .filter(Task.status != "Completed").count(),
        "total_estate_value": total_estate_value,
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
        category_totals=sorted_categories,
        total_estate_value=total_estate_value,
    )


# ---------------------------------------------------------------------------
# Asset Management (Step 4)
# ---------------------------------------------------------------------------
@app.route("/assets")
@login_required
def assets_list():
    user = current_user()
    assets = Asset.query.filter_by(user_id=user.id).order_by(Asset.created_at.desc()).all()
    total_estate_value = sum(a.approx_value or 0 for a in assets)
    return render_template("assets.html", assets=assets, total_estate_value=total_estate_value)


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
            wallet_address=request.form.get("wallet_address", "").strip() or None,
            last_synced_at=datetime.utcnow(),
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
        asset.wallet_address = request.form.get("wallet_address", "").strip() or None

        db.session.commit()
        flash("Asset updated.", "success")
        return redirect(url_for("assets_list"))

    return render_template("asset_form.html", asset=asset)


@app.route("/assets/sync", methods=["POST"])
@login_required
def assets_sync():
    """Step & Feature 5: Synchronize asset valuations / crypto balances."""
    user = current_user()
    assets = Asset.query.filter_by(user_id=user.id).all()
    now = datetime.utcnow()
    synced_crypto = 0

    for a in assets:
        a.last_synced_at = now
        if a.wallet_address and _ADDRESS_RE.fullmatch(a.wallet_address):
            try:
                # Query Polygon Amoy RPC for live balance
                payload = json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_getBalance",
                    "params": [a.wallet_address, "latest"],
                }).encode()
                req = urllib.request.Request(
                    POLYGON_AMOY_RPC_URL, data=payload, headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    res = json.loads(resp.read().decode())
                hex_bal = res.get("result", "0x0")
                wei = int(hex_bal, 16)
                pol = wei / 10**18
                # Approximate demonstration conversion: 1 POL = ~50 INR / ~0.60 USD
                if pol > 0:
                    a.approx_value = round(pol * 50.0, 2)
                synced_crypto += 1
            except Exception:
                pass

    db.session.commit()
    if synced_crypto > 0:
        flash(f"Asset valuations synchronized ({synced_crypto} blockchain address(es) updated).", "success")
    else:
        flash("Asset valuations refreshed and synchronized.", "success")
    return redirect(url_for("assets_list"))


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
    updated = False
    for n in nominees:
        if not n.claim_token:
            n.claim_token = secrets.token_hex(20)
            updated = True
    if updated:
        db.session.commit()
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
            claim_token=secrets.token_hex(20),
        )

        if not nominee.name or not nominee.relationship_:
            flash("Please add the nominee's name and their relationship to you.", "danger")
            return redirect(url_for("nominee_add"))

        db.session.add(nominee)
        db.session.commit()
        flash("Nominee added.", "success")
        return redirect(url_for("nominees_list"))

    return render_template("nominee_form.html", nominee=None)


# ---------------------------------------------------------------------------
# Scoped Nominee / Executor Claim Portal (Feature 4)
# ---------------------------------------------------------------------------
@app.route("/claim/<token>")
def claim_portal(token):
    """Scoped portal for a designated beneficiary. Zero exposure of other nominees."""
    nominee = Nominee.query.filter_by(claim_token=token).first_or_404()
    owner = User.query.get(nominee.user_id)
    if not owner:
        abort(404)

    life = owner.life_verification
    is_unlocked = bool(
        life and (life.status == "VAULT_UNLOCKED" or life.probate_status == "UNLOCKED")
    )
    is_preview = (request.args.get("preview") == "1" and session.get("user_id") == owner.id)

    # Strictly scoped assets
    scoped_assets = nominee.assets

    # Strictly scoped will instructions
    scoped_instructions = [
        inst for inst in owner.will_instructions
        if (inst.beneficiary_name and inst.beneficiary_name.strip().lower() == nominee.name.strip().lower())
        or (inst.asset and inst.asset in scoped_assets)
    ]

    # Documents pertinent to owner's vault
    scoped_documents = Document.query.filter_by(user_id=owner.id).all()

    return render_template(
        "claim_portal.html",
        nominee=nominee,
        owner=owner,
        is_unlocked=(is_unlocked or is_preview),
        is_preview=is_preview,
        assets=scoped_assets,
        instructions=scoped_instructions,
        documents=scoped_documents,
    )


@app.route("/claim/<token>/document/<int:document_id>")
def claim_document_download(token, document_id):
    nominee = Nominee.query.filter_by(claim_token=token).first_or_404()
    owner = User.query.get(nominee.user_id)
    if not owner:
        abort(404)
    life = owner.life_verification
    is_unlocked = bool(
        life and (life.status == "VAULT_UNLOCKED" or life.probate_status == "UNLOCKED")
    )
    is_preview = (request.args.get("preview") == "1" and session.get("user_id") == owner.id)
    if not (is_unlocked or is_preview):
        flash("Vault is sealed. Documents cannot be released until life verification quorum is met.", "danger")
        return redirect(url_for("claim_portal", token=token))

    doc = Document.query.filter_by(id=document_id, user_id=owner.id).first_or_404()
    return send_from_directory(
        UPLOAD_DIR,
        doc.stored_filename,
        as_attachment=True,
        download_name=doc.original_filename,
    )


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


@app.route("/will/export-dossier-pdf")
@login_required
def export_dossier_pdf():
    """Feature 3: Generate a court-ready, cryptographically stamped estate PDF."""
    user = current_user()
    assets = Asset.query.filter_by(user_id=user.id).all()
    instructions = WillInstruction.query.filter_by(user_id=user.id).all()
    documents = Document.query.filter_by(user_id=user.id).all()
    digital_accounts = DigitalAccount.query.filter_by(user_id=user.id).all()
    tasks = Task.query.filter_by(user_id=user.id).all()
    completeness = compute_will_completeness(user)

    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    primary_color = colors.HexColor("#2F4A3E")
    sand_bg = colors.HexColor("#F7F3EA")
    ink_color = colors.HexColor("#26312C")
    muted_ink = colors.HexColor("#5B6B60")

    title_style = ParagraphStyle(
        "DossierTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=primary_color,
        spaceAfter=3,
    )
    subtitle_style = ParagraphStyle(
        "DossierSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=muted_ink,
        spaceAfter=10,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=ink_color,
    )
    body_bold = ParagraphStyle(
        "BodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    small_muted = ParagraphStyle(
        "SmallMuted",
        parent=body_style,
        fontSize=7.5,
        leading=10,
        textColor=muted_ink,
    )

    story = []

    # QR Code generation
    dossier_id = uuid.uuid4().hex[:12].upper()
    qr_data = (
        f"DL-Vault Verified Dossier\n"
        f"Testator: {user.full_name}\n"
        f"Email: {user.email}\n"
        f"Dossier ID: {dossier_id}\n"
        f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n"
        f"Will Completeness: {completeness['percent']}%\n"
        f"Blockchain: Polygon Amoy Testnet (80002)"
    )
    qr_img = qrcode.make(qr_data)
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)
    rl_qr = RLImage(qr_buf, width=0.9 * inch, height=0.9 * inch)

    header_table_data = [
        [
            [
                Paragraph("DIGITAL LEGACY VAULT & LAST WILL DOSSIER", title_style),
                Paragraph(
                    f"Testamentary Directives & Verified Asset Inventory &bull; <b>{user.full_name}</b> ({user.email})<br/>"
                    f"Dossier Ref: <b>{dossier_id}</b> &bull; Generated: <b>{datetime.utcnow().strftime('%B %d, %Y')}</b> &bull; Completeness Score: <b>{completeness['percent']}%</b>",
                    subtitle_style,
                ),
            ],
            rl_qr,
        ]
    ]
    header_table = Table(header_table_data, colWidths=[445, 95])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=primary_color, spaceAfter=8))

    declaration_text = (
        f"I, <b>{user.full_name}</b>, registered with account identifier <i>{user.email}</i>, declare this document to be "
        "my comprehensive testamentary estate catalog and digital asset directives inventory. "
        "The designations, beneficiary instructions, and cryptographic proofs recorded herein reflect my intended distributions "
        "and post-probate estate execution orders."
    )
    story.append(Paragraph(declaration_text, body_style))
    story.append(Spacer(1, 8))

    # 1. Assets
    story.append(Paragraph("1. Cataloged Assets & Designated Nominees", section_heading))
    if assets:
        asset_rows = [[
            Paragraph("Asset Name", body_bold),
            Paragraph("Category", body_bold),
            Paragraph("Institution / Reference", body_bold),
            Paragraph("Approx. Value", body_bold),
            Paragraph("Designated Nominees", body_bold),
        ]]
        for a in assets:
            nom_names = ", ".join(n.name for n in a.nominees) if a.nominees else "None assigned"
            val_str = f"₹{a.approx_value:,.2f}" if a.approx_value else "—"
            asset_rows.append([
                Paragraph(a.name, body_style),
                Paragraph(a.category, body_style),
                Paragraph(f"{a.provider or '—'}<br/><font size='7'>{a.reference or ''}</font>", body_style),
                Paragraph(val_str, body_style),
                Paragraph(nom_names, body_style),
            ])
        t_assets = Table(asset_rows, colWidths=[120, 85, 125, 80, 130])
        t_assets.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sand_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D3C7A8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_assets)
    else:
        story.append(Paragraph("<i>No assets registered in this vault.</i>", body_style))
    story.append(Spacer(1, 8))

    # 2. Will Instructions
    story.append(Paragraph("2. Testamentary Instructions & Beneficiary Allocations", section_heading))
    if instructions:
        inst_rows = [[
            Paragraph("Tied Asset", body_bold),
            Paragraph("Designated Beneficiary", body_bold),
            Paragraph("Testamentary Instruction Directive", body_bold),
        ]]
        for ins in instructions:
            asset_name = ins.asset.name if ins.asset else "General Estate (Unallocated)"
            inst_rows.append([
                Paragraph(asset_name, body_style),
                Paragraph(ins.beneficiary_name, body_style),
                Paragraph(ins.instruction_text, body_style),
            ])
        t_inst = Table(inst_rows, colWidths=[130, 110, 300])
        t_inst.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sand_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D3C7A8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_inst)
    else:
        story.append(Paragraph("<i>No specific will instructions recorded.</i>", body_style))
    story.append(Spacer(1, 8))

    # 3. Digital Legacy
    story.append(Paragraph("3. Digital Accounts & Online Legacy Directives", section_heading))
    if digital_accounts:
        da_rows = [[
            Paragraph("Platform / Service", body_bold),
            Paragraph("Account Identifier", body_bold),
            Paragraph("Action", body_bold),
            Paragraph("Beneficiary", body_bold),
            Paragraph("Directive Notes", body_bold),
        ]]
        for da in digital_accounts:
            enc_tag = "<br/><font color='#C1793F'><b>[Zero-Knowledge Encrypted]</b></font>" if da.is_encrypted else ""
            da_rows.append([
                Paragraph(da.service, body_style),
                Paragraph(da.account_identifier, body_style),
                Paragraph(da.action, body_style),
                Paragraph(da.beneficiary or "—", body_style),
                Paragraph((da.instructions or "None") + enc_tag, body_style),
            ])
        t_da = Table(da_rows, colWidths=[100, 110, 70, 90, 170])
        t_da.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sand_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D3C7A8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_da)
    else:
        story.append(Paragraph("<i>No digital legacy accounts recorded.</i>", body_style))
    story.append(Spacer(1, 8))

    # 4. Document Manifest
    story.append(Paragraph("4. Document Manifest & Cryptographic Fingerprints", section_heading))
    if documents:
        doc_rows = [[
            Paragraph("Document File", body_bold),
            Paragraph("Category", body_bold),
            Paragraph("SHA-256 Digest", body_bold),
            Paragraph("Proof Status", body_bold),
        ]]
        for d in documents:
            p = d.proof
            sha_display = f"<font face='Courier' size='6.5'>{p.sha256_hash}</font>" if p else "Unsealed"
            status_display = p.status if p else "Standard Upload"
            if p and p.tx_hash:
                status_display += f"<br/><font size='6' color='#2F4A3E'>Tx: {p.tx_hash[:16]}...</font>"
            doc_rows.append([
                Paragraph(d.original_filename, body_style),
                Paragraph(d.category, body_style),
                Paragraph(sha_display, body_style),
                Paragraph(status_display, body_style),
            ])
        t_doc = Table(doc_rows, colWidths=[120, 80, 240, 100])
        t_doc.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sand_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D3C7A8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_doc)
    else:
        story.append(Paragraph("<i>No documents attached to this vault.</i>", body_style))
    story.append(Spacer(1, 10))

    # 5. Attestation & Signatures
    sig_block = [
        [
            Paragraph("<b>Testator Signature:</b><br/><br/><br/>_____________________________________<br/>" + user.full_name + "<br/>Date: ________________________", body_style),
            Paragraph("<b>Witness 1 Attestation:</b><br/><br/><br/>_____________________________________<br/>Name: ________________________<br/>Date: ________________________", body_style),
            Paragraph("<b>Witness 2 Attestation:</b><br/><br/><br/>_____________________________________<br/>Name: ________________________<br/>Date: ________________________", body_style),
        ]
    ]
    t_sig = Table(sig_block, colWidths=[180, 180, 180])
    t_sig.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(KeepTogether([
        Paragraph("5. Legal Execution & Attestation", section_heading),
        Spacer(1, 4),
        t_sig,
        Spacer(1, 6),
        Paragraph("<font size='7' color='#5B6B60'>* This dossier is an inventory and declaration artifact produced by the Digital Legacy Vault. For formal court probate, ensure local testamentary execution standards are fulfilled.</font>", small_muted),
    ]))

    doc.build(story)
    pdf_buffer.seek(0)
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', user.full_name)
    filename = f"Estate_Dossier_{safe_name}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return send_file(pdf_buffer, mimetype="application/pdf", as_attachment=True, download_name=filename)


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
        is_enc = request.form.get("is_encrypted") in ("1", "true", "on")
        enc_notes = request.form.get("encrypted_notes", "").strip() if is_enc else None
        instructions = request.form.get("instructions", "").strip()
        if is_enc and not instructions:
            instructions = "[Zero-Knowledge Encrypted Directives]"

        account = DigitalAccount(
            user_id=user.id,
            service=request.form.get("service", "").strip(),
            account_identifier=request.form.get("account_identifier", "").strip(),
            action=request.form.get("action", "").strip(),
            beneficiary=request.form.get("beneficiary", "").strip(),
            instructions=instructions,
            is_encrypted=is_enc,
            encrypted_notes=enc_notes,
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
        is_enc = request.form.get("is_encrypted") in ("1", "true", "on")
        instructions = request.form.get("instructions", "").strip()
        enc_notes = request.form.get("encrypted_notes", "").strip() if is_enc else None
        if is_enc and not instructions:
            instructions = "[Zero-Knowledge Encrypted Directives]"

        account.service = service
        account.account_identifier = identifier
        account.action = action
        account.beneficiary = request.form.get("beneficiary", "").strip()
        account.instructions = instructions
        account.is_encrypted = is_enc
        account.encrypted_notes = enc_notes

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
    updated = False
    for c in contacts:
        if not c.approval_token:
            c.approval_token = secrets.token_hex(20)
            updated = True
    if updated:
        db.session.commit()
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
            approval_token=secrets.token_hex(20),
        )

        if not contact.name or not contact.relationship_:
            flash("Please add a name and how they're connected to you.", "danger")
            return redirect(url_for("trusted_contact_add"))

        db.session.add(contact)
        db.session.commit()
        flash("Trusted contact added.", "success")
        return redirect(url_for("trusted_contacts_list"))

    return render_template("trusted_contact_form.html", contact=None)


# ---------------------------------------------------------------------------
# Trusted Contact Review & Quorum Approval Protocol (Feature 2)
# ---------------------------------------------------------------------------
@app.route("/trusted-contact/review/<token>")
def trusted_contact_review(token):
    contact = TrustedContact.query.filter_by(approval_token=token).first_or_404()
    owner = User.query.get(contact.user_id)
    if not owner:
        abort(404)
    life = owner.life_verification
    approved_count = TrustedContact.query.filter_by(user_id=owner.id, approval_status="APPROVED").count()
    total_contacts = TrustedContact.query.filter_by(user_id=owner.id).count()

    return render_template(
        "trusted_contact_review.html",
        contact=contact,
        owner=owner,
        life=life,
        approved_count=approved_count,
        total_contacts=total_contacts,
    )


@app.route("/trusted-contact/review/<token>/action", methods=["POST"])
def trusted_contact_review_action(token):
    contact = TrustedContact.query.filter_by(approval_token=token).first_or_404()
    owner = User.query.get(contact.user_id)
    if not owner:
        abort(404)
    life = owner.life_verification
    decision = request.form.get("decision", "").strip()
    notes = request.form.get("notes", "").strip()

    if decision == "approve":
        contact.approval_status = "APPROVED"
        contact.approval_notes = notes
        contact.approved_at = datetime.utcnow()
        db.session.commit()

        # Check if quorum is fulfilled
        approved_count = TrustedContact.query.filter_by(user_id=owner.id, approval_status="APPROVED").count()
        quorum_target = life.quorum_required if life else 2
        if approved_count >= quorum_target:
            if life:
                life.status = "VAULT_UNLOCKED"
                life.probate_status = "UNLOCKED"
                db.session.commit()
        flash("Thank you. Your confirmation has been recorded in the vault quorum ledger.", "success")
    elif decision == "reject":
        contact.approval_status = "REJECTED"
        contact.approval_notes = notes
        contact.approved_at = datetime.utcnow()
        db.session.commit()
        flash("Thank you. Your feedback has been noted and vault access remains locked.", "info")
    else:
        flash("Invalid decision.", "danger")

    return redirect(url_for("trusted_contact_review", token=token))


# ---------------------------------------------------------------------------
# Life Verification (Step 11) & Multi-Party Quorum (Feature 2)
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
            quorum_required=2,
            probate_status="NORMAL",
        )
        db.session.add(record)
        db.session.commit()
    return record


@app.route("/life-verification")
@login_required
def life_verification():
    user = current_user()
    record = get_or_create_verification(user)
    contacts = TrustedContact.query.filter_by(user_id=user.id).all()
    # Backfill tokens if any are missing
    updated = False
    for c in contacts:
        if not c.approval_token:
            c.approval_token = secrets.token_hex(20)
            updated = True
    if updated:
        db.session.commit()

    if record.next_verification_due < datetime.utcnow() and record.status == "OK":
        record.status = "VERIFICATION_REQUIRED"
        db.session.commit()

    seconds_left = (record.next_verification_due - datetime.utcnow()).total_seconds()
    days_left = int(seconds_left / 86400)
    approved_count = sum(1 for c in contacts if c.approval_status == "APPROVED")

    return render_template(
        "life_verification.html",
        record=record,
        days_left=days_left,
        contacts=contacts,
        approved_count=approved_count,
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
    record.probate_status = "NORMAL"
    record.probate_requested_at = None
    # Reset trusted contact approvals on owner check-in
    for c in user.trusted_contacts:
        c.approval_status = "PENDING"
        c.approval_notes = None
        c.approved_at = None
    db.session.commit()

    flash("Thank you — you're checked in. Your check-in timer and quorum state have been reset.", "success")
    return redirect(url_for("life_verification"))


@app.route("/life-verification/reset-quorum", methods=["POST"])
@login_required
def life_verification_reset_quorum():
    """Emergency owner override to dismiss false alarms and reset quorum."""
    user = current_user()
    record = get_or_create_verification(user)
    record.status = "OK"
    record.probate_status = "NORMAL"
    record.probate_requested_at = None
    for c in user.trusted_contacts:
        c.approval_status = "PENDING"
        c.approval_notes = None
        c.approved_at = None
    db.session.commit()
    flash("Emergency override activated: Vault returned to NORMAL state. All quorum approvals cleared.", "success")
    return redirect(url_for("life_verification"))


@app.route("/life-verification/initiate-probate", methods=["POST"])
@login_required
def life_verification_initiate_probate():
    """Simulate/trigger quorum approval process across trusted contacts."""
    user = current_user()
    record = get_or_create_verification(user)
    record.status = "VERIFICATION_REQUIRED"
    record.probate_status = "PENDING_APPROVAL"
    record.probate_requested_at = datetime.utcnow()
    for c in user.trusted_contacts:
        c.approval_status = "PENDING"
    db.session.commit()
    flash("Quorum protocol initiated. Trusted contacts may now review and approve vault unlock.", "warning")
    return redirect(url_for("life_verification"))


@app.route("/life-verification/quorum-settings", methods=["POST"])
@login_required
def life_verification_quorum_settings():
    user = current_user()
    record = get_or_create_verification(user)
    try:
        val = int(request.form.get("quorum_required", 2))
        record.quorum_required = max(1, val)
        db.session.commit()
        flash("Quorum threshold updated.", "success")
    except ValueError:
        flash("Invalid quorum number.", "danger")
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
# Command Palette Search API (Part 2 UI Feature 6)
# ---------------------------------------------------------------------------
@app.route("/api/quick-search")
@login_required
def quick_search_api():
    user = current_user()
    q = request.args.get("q", "").strip().lower()
    results = []

    # Quick actions
    actions = [
        {"title": "Add New Asset", "category": "Action", "url": url_for("asset_add")},
        {"title": "Add Nominee", "category": "Action", "url": url_for("nominee_add")},
        {"title": "Add Will Instruction", "category": "Action", "url": url_for("will_add")},
        {"title": "Upload Document", "category": "Action", "url": url_for("document_upload")},
        {"title": "Add Digital Account", "category": "Action", "url": url_for("digital_account_add")},
        {"title": "Export Court-Ready Dossier (PDF)", "category": "Action", "url": url_for("export_dossier_pdf")},
        {"title": "Open Will Checker", "category": "Navigation", "url": url_for("will_checker")},
        {"title": "Life Verification & Quorum", "category": "Navigation", "url": url_for("life_verification")},
        {"title": "Inheritance Tasks", "category": "Navigation", "url": url_for("tasks_list")},
    ]

    for a in actions:
        if not q or q in a["title"].lower() or q in a["category"].lower():
            results.append(a)

    if q:
        # Search assets
        assets = Asset.query.filter(
            Asset.user_id == user.id,
            (Asset.name.ilike(f"%{q}%")) | (Asset.category.ilike(f"%{q}%"))
        ).limit(5).all()
        for ast in assets:
            results.append({
                "title": f"{ast.name} ({ast.category})",
                "category": "Asset",
                "url": url_for("asset_edit", asset_id=ast.id),
            })

        # Search nominees
        nominees = Nominee.query.filter(
            Nominee.user_id == user.id,
            Nominee.name.ilike(f"%{q}%")
        ).limit(5).all()
        for nom in nominees:
            results.append({
                "title": f"{nom.name} ({nom.relationship_})",
                "category": "Nominee",
                "url": url_for("nominee_edit", nominee_id=nom.id),
            })

        # Search documents
        docs = Document.query.filter(
            Document.user_id == user.id,
            (Document.original_filename.ilike(f"%{q}%")) | (Document.category.ilike(f"%{q}%"))
        ).limit(5).all()
        for d in docs:
            results.append({
                "title": f"{d.original_filename} ({d.category})",
                "category": "Document",
                "url": url_for("documents_list"),
            })

        # Search digital accounts
        accs = DigitalAccount.query.filter(
            DigitalAccount.user_id == user.id,
            (DigitalAccount.service.ilike(f"%{q}%")) | (DigitalAccount.account_identifier.ilike(f"%{q}%"))
        ).limit(5).all()
        for acc in accs:
            results.append({
                "title": f"{acc.service}: {acc.account_identifier}",
                "category": "Digital Legacy",
                "url": url_for("digital_account_edit", account_id=acc.id),
            })

    return jsonify(results=results[:12])


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
# Entry point & schema migration
# ---------------------------------------------------------------------------
def _ensure_schema():
    with app.app_context():
        db.create_all()
        try:
            with db.engine.connect() as conn:
                tables_cols = [
                    ("assets", [("wallet_address", "VARCHAR(120)"), ("last_synced_at", "DATETIME")]),
                    ("nominees", [("claim_token", "VARCHAR(64)")]),
                    ("digital_accounts", [("is_encrypted", "BOOLEAN DEFAULT 0"), ("encrypted_notes", "TEXT")]),
                    ("trusted_contacts", [("approval_token", "VARCHAR(64)"), ("approval_status", "VARCHAR(20) DEFAULT 'PENDING'"), ("approval_notes", "TEXT"), ("approved_at", "DATETIME")]),
                    ("life_verifications", [("quorum_required", "INTEGER DEFAULT 2"), ("probate_status", "VARCHAR(30) DEFAULT 'NORMAL'"), ("probate_requested_at", "DATETIME")]),
                ]
                for table, cols in tables_cols:
                    res = conn.execute(db.text(f"PRAGMA table_info({table})")).fetchall()
                    existing = {row[1] for row in res}
                    for col_name, col_type in cols:
                        if col_name not in existing:
                            conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                            conn.commit()

            # Backfill any null tokens in Nominee and TrustedContact
            nominees_no_tok = Nominee.query.filter((Nominee.claim_token == None) | (Nominee.claim_token == "")).all()
            for n in nominees_no_tok:
                n.claim_token = secrets.token_hex(20)
            contacts_no_tok = TrustedContact.query.filter((TrustedContact.approval_token == None) | (TrustedContact.approval_token == "")).all()
            for c in contacts_no_tok:
                c.approval_token = secrets.token_hex(20)
            if nominees_no_tok or contacts_no_tok:
                db.session.commit()
        except Exception as e:
            print(f"[schema migration notice] {e}")


_ensure_schema()


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/acceptable-use")
def acceptable_use():
    return render_template("acceptable_use.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        if not name or not email or not message:
            flash("Please fill in your name, email, and message.", "danger")
        else:
            flash("Thank you for reaching out. Your message has been received and our team will respond within 2-3 business days.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/healthz")
def healthz():
    """Plain 'ok' for the hosting platform's health check. No data, no login."""
    return "ok", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    # Debug mode is for local development only — never on a real deployment.
    app.run(debug=not IS_PRODUCTION)
