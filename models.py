from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    assets = db.relationship("Asset", backref="owner", cascade="all, delete-orphan")
    nominees = db.relationship("Nominee", backref="owner", cascade="all, delete-orphan")
    will_instructions = db.relationship(
        "WillInstruction", backref="owner", cascade="all, delete-orphan"
    )
    documents = db.relationship(
        "Document", backref="owner", cascade="all, delete-orphan"
    )
    digital_accounts = db.relationship(
        "DigitalAccount", backref="owner", cascade="all, delete-orphan"
    )
    trusted_contacts = db.relationship(
        "TrustedContact", backref="owner", cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    provider = db.Column(db.String(120))
    reference = db.Column(db.String(120))
    approx_value = db.Column(db.Float, default=0)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    nominees = db.relationship(
        "Nominee", secondary="asset_nominee", back_populates="assets"
    )
    will_instructions = db.relationship(
        "WillInstruction", backref="asset", cascade="all, delete-orphan"
    )


class Nominee(db.Model):
    __tablename__ = "nominees"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    name = db.Column(db.String(120), nullable=False)
    relationship_ = db.Column("relationship", db.String(80), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(30))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    assets = db.relationship(
        "Asset", secondary="asset_nominee", back_populates="nominees"
    )


# Many-to-many link table between assets and nominees
asset_nominee = db.Table(
    "asset_nominee",
    db.Column("asset_id", db.Integer, db.ForeignKey("assets.id"), primary_key=True),
    db.Column("nominee_id", db.Integer, db.ForeignKey("nominees.id"), primary_key=True),
)


class WillInstruction(db.Model):
    __tablename__ = "will_instructions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)

    beneficiary_name = db.Column(db.String(120), nullable=False)
    instruction_text = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    file_size = db.Column(db.Integer, default=0)

    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    proof = db.relationship(
        "DocumentProof",
        backref="document",
        uselist=False,
        cascade="all, delete-orphan",
    )


class DocumentProof(db.Model):
    """
    Step 12/Phase E — Blockchain document notarization (optional, opt-in).

    At most one row per Document. Recorded only when the user explicitly
    chooses to notarize a document. Stores nothing but a fingerprint of
    the file (SHA-256), where the file was pinned on IPFS (its CID), and
    the on-chain transaction that registered that fingerprint — never
    the document's contents and never personal data.

    A document with no DocumentProof row (or with is_notarized False)
    simply has never been notarized; this is the normal, expected state
    for most documents and is never required.
    """
    __tablename__ = "document_proofs"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=False, unique=True
    )

    sha256_hash = db.Column(db.String(64), nullable=False)
    ipfs_cid = db.Column(db.String(255))
    tx_hash = db.Column(db.String(255))
    wallet_address = db.Column(db.String(64))
    network = db.Column(db.String(60), default="polygon-amoy-testnet")

    # PENDING     -> hashed/uploaded to IPFS, on-chain transaction not yet confirmed
    # NOTARIZED   -> transaction confirmed, hash is recorded on-chain
    # FAILED      -> attempt was made but did not complete (safe to retry)
    # SEALED      -> Integrity Seal: fingerprint saved privately in the vault, no
    #                wallet or blockchain involved (network == "local-seal")
    status = db.Column(db.String(20), default="PENDING", nullable=False)

    notarized_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_notarized(self):
        return self.status == "NOTARIZED" and bool(self.tx_hash)


class DigitalAccount(db.Model):
    __tablename__ = "digital_accounts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    service = db.Column(db.String(120), nullable=False)
    account_identifier = db.Column(db.String(160), nullable=False)
    action = db.Column(db.String(40), nullable=False)  # Preserve / Delete / Transfer / Memorialize
    beneficiary = db.Column(db.String(120))
    instructions = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TrustedContact(db.Model):
    __tablename__ = "trusted_contacts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    name = db.Column(db.String(120), nullable=False)
    relationship_ = db.Column("relationship", db.String(80), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(30))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LifeVerification(db.Model):
    """
    Step 11 — Life Verification (simulation only).

    One row per user. Tracks the last time the user confirmed they are
    alive and the next date by which they must confirm again. This is a
    SIMULATION: nothing is ever automatically released. Missing a
    verification only flips the status to VERIFICATION_REQUIRED.
    """
    __tablename__ = "life_verifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)

    last_verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    next_verification_due = db.Column(db.DateTime, nullable=False)

    # OK  -> next_verification_due is in the future
    # VERIFICATION_REQUIRED -> user missed the check-in (simulated or real)
    status = db.Column(db.String(30), default="OK", nullable=False)

    verification_interval_days = db.Column(db.Integer, default=30, nullable=False)

    owner = db.relationship("User", backref=db.backref(
        "life_verification", uselist=False, cascade="all, delete-orphan"
    ))


class Task(db.Model):
    """Step 12 — Inheritance Tasks (post-inheritance checklist)."""
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="Pending", nullable=False)  # Pending / In Progress / Completed

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
