"""
seed_demo.py — Step 21

Fills the Digital Legacy Vault with one realistic demo account that touches
EVERY feature, so a fresh clone can be explored in a single command:

    python seed_demo.py            # create the demo account (skips if present)
    python seed_demo.py --reset    # delete the demo account, then re-create it

Then log in with:  demo@vault.local  /  demo1234

What gets created
-----------------
  * 6 assets (categories match the Add-Asset dropdown exactly)
  * 3 nominees, linked to assets (many-to-many)
  * 6 will instructions (one is not tied to a specific asset)
  * 3 documents, each with a REAL file on disk so Download works
    (the property deed also carries a notarization fingerprint, status PENDING)
  * 5 digital accounts covering all four actions (Preserve / Memorialize /
    Transfer / Delete)
  * 2 trusted contacts
  * a life-verification record, checked in and healthy
  * 6 inheritance tasks across all three statuses

Deliberately incomplete on purpose
----------------------------------
"Mutual Fund" has NO nominee and NO will instruction, so the Will Checker
has real warnings to show (rule 1: asset has an instruction, rule 3: asset
has a nominee). Everything else is fully linked, so the completeness score
lands somewhere believable rather than 0% or 100%.

Safety
------
Only the demo user (demo@vault.local) is ever touched. --reset deletes that
one account and the files it owns; no other user's data is read or changed.
"""
import hashlib
import os
import sys
import uuid
from datetime import datetime, timedelta

from app import app, UPLOAD_DIR
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

DEMO_EMAIL = "demo@vault.local"
DEMO_PASSWORD = "demo1234"


# ---------------------------------------------------------------------------
# Tiny but VALID sample files. The upload route checks a file's leading bytes
# match its extension, so these use genuine signatures. They open normally in
# a PDF reader / image viewer.
# ---------------------------------------------------------------------------
def _sample_pdf(title):
    """A minimal, valid one-page PDF with the given title as its text."""
    text = title.replace("(", "").replace(")", "")
    stream = f"BT /F1 20 Tf 60 720 Td ({text}) Tj ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode()
    xref_at = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return out


def _sample_png():
    """A valid 1x1 PNG (a single warm cream pixel)."""
    import struct
    import zlib

    def chunk(kind, data):
        body = kind + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    raw = b"\x00" + bytes([0xF6, 0xF1, 0xE6])  # filter byte + RGB
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def _write_upload(ext, data):
    """Save bytes under a random UUID name, exactly like a real upload."""
    stored = f"{uuid.uuid4().hex}.{ext}"
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as fh:
        fh.write(data)
    return stored, len(data)


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------
def _delete_demo_user():
    """Remove the demo user, their rows, and their files on disk."""
    user = User.query.filter_by(email=DEMO_EMAIL).first()
    if not user:
        return False

    # Files first (the DB rows cascade-delete with the user).
    for doc in Document.query.filter_by(user_id=user.id).all():
        path = os.path.join(UPLOAD_DIR, doc.stored_filename)
        if os.path.isfile(path):
            os.remove(path)

    # Clear the many-to-many links, then the user (cascades everything else).
    for asset in Asset.query.filter_by(user_id=user.id).all():
        asset.nominees = []
    db.session.commit()

    db.session.delete(user)
    db.session.commit()
    return True


# ---------------------------------------------------------------------------
# Seed
# ---------------------------------------------------------------------------
def seed(reset=False):
    with app.app_context():
        db.create_all()

        if reset:
            if _delete_demo_user():
                print("Removed the existing demo account and its files.")

        existing = User.query.filter_by(email=DEMO_EMAIL).first()
        if existing:
            print(f"Demo user already exists ({DEMO_EMAIL}). Nothing changed.")
            print("Run `python seed_demo.py --reset` to rebuild it from scratch.")
            print(f"Login with: {DEMO_EMAIL} / {DEMO_PASSWORD}")
            return

        # --- User ------------------------------------------------------
        user = User(full_name="Demo User", email=DEMO_EMAIL)
        user.set_password(DEMO_PASSWORD)
        db.session.add(user)
        db.session.commit()
        uid = user.id

        # --- Assets (categories match the Add-Asset dropdown) ---------
        home = Asset(
            user_id=uid, name="Family Home", category="Property",
            provider="Self-owned", reference="Flat 402, Andheri West",
            approx_value=8500000, description="2BHK apartment, freehold.",
        )
        savings = Asset(
            user_id=uid, name="Savings Account", category="Bank Account",
            provider="HDFC Bank", reference="A/C ****4521",
            approx_value=350000, description="Primary savings account.",
        )
        policy = Asset(
            user_id=uid, name="Term Life Policy", category="Insurance",
            provider="LIC", reference="Policy 998877",
            approx_value=2000000, description="20-year term life cover.",
        )
        car = Asset(
            user_id=uid, name="Family Car", category="Vehicle",
            provider="Self-owned", reference="MH-31-AB-1234",
            approx_value=650000, description="Hatchback, second owner.",
        )
        retirement = Asset(
            user_id=uid, name="Retirement Fund", category="Investment",
            provider="EPFO", reference="UAN 1012 3456 7890",
            approx_value=1200000, description="Employee provident fund.",
        )
        # INTENTIONALLY INCOMPLETE — no nominee, no will instruction.
        mutual_fund = Asset(
            user_id=uid, name="Mutual Fund", category="Investment",
            provider="HDFC Mutual Fund", reference="Folio 55221100",
            approx_value=420000, description="Monthly SIP portfolio.",
        )
        db.session.add_all([home, savings, policy, car, retirement, mutual_fund])
        db.session.commit()

        # --- Nominees -------------------------------------------------
        mother = Nominee(user_id=uid, name="Asha Rao", relationship_="Mother",
                         email="asha@example.com", phone="9800000001")
        father = Nominee(user_id=uid, name="Vikram Rao", relationship_="Father",
                         email="vikram@example.com", phone="9800000002")
        brother = Nominee(user_id=uid, name="Rohan Rao", relationship_="Brother",
                          email="rohan@example.com", phone="9800000003")
        db.session.add_all([mother, father, brother])
        db.session.commit()

        # Many-to-many links. Note: an asset can have more than one nominee.
        home.nominees.extend([mother, father])
        savings.nominees.append(brother)
        policy.nominees.append(father)
        car.nominees.append(mother)
        retirement.nominees.append(brother)
        # mutual_fund gets none, on purpose.
        db.session.commit()

        # --- Will instructions ----------------------------------------
        db.session.add_all([
            WillInstruction(
                user_id=uid, asset_id=home.id, beneficiary_name="Asha Rao",
                instruction_text="Transfer the family home to my mother, to live "
                                 "in for as long as she wishes.",
            ),
            WillInstruction(
                user_id=uid, asset_id=savings.id, beneficiary_name="Rohan Rao",
                instruction_text="Transfer the savings balance to my brother.",
            ),
            WillInstruction(
                user_id=uid, asset_id=policy.id, beneficiary_name="Vikram Rao",
                instruction_text="Insurance claim to be handled by my father.",
            ),
            WillInstruction(
                user_id=uid, asset_id=car.id, beneficiary_name="Asha Rao",
                instruction_text="The car goes to my mother.",
            ),
            WillInstruction(
                user_id=uid, asset_id=retirement.id, beneficiary_name="Rohan Rao",
                instruction_text="The retirement fund goes to my brother.",
            ),
            # Not tied to any one asset — shows the optional link is optional.
            WillInstruction(
                user_id=uid, asset_id=None, beneficiary_name="Rohan Rao",
                instruction_text="Please look after my mother and father, and "
                                 "keep the family photographs together.",
            ),
        ])
        db.session.commit()

        # --- Documents (real files on disk) ---------------------------
        docs = [
            ("Property-Deed.pdf", "pdf", "Property Papers",
             "Registered sale deed for the family home.",
             _sample_pdf("Property Deed - Family Home (demo)")),
            ("LIC-Policy-Schedule.pdf", "pdf", "Insurance",
             "Policy schedule and premium receipts.",
             _sample_pdf("LIC Term Policy 998877 (demo)")),
            ("Passport-Scan.png", "png", "Identity Proof",
             "Scanned passport photo page.",
             _sample_png()),
        ]
        for original, ext, category, description, data in docs:
            stored, size = _write_upload(ext, data)
            doc = Document(
                user_id=uid, original_filename=original, stored_filename=stored,
                category=category, description=description, file_size=size,
            )
            # The property deed opts in to notarization, so a fresh clone shows
            # that feature. Fingerprint only — no IPFS, the file stays private.
            if original == "Property-Deed.pdf":
                doc.proof = DocumentProof(
                    sha256_hash=hashlib.sha256(data).hexdigest(),
                    ipfs_cid=None,
                    status="PENDING",
                )
            db.session.add(doc)
        db.session.commit()

        # --- Digital accounts: all four actions -----------------------
        db.session.add_all([
            DigitalAccount(
                user_id=uid, service="Google", account_identifier="demo@gmail.com",
                action="Preserve", beneficiary="Rohan Rao",
                instructions="Keep it active — it holds the family photos.",
            ),
            DigitalAccount(
                user_id=uid, service="Facebook", account_identifier="demo.user",
                action="Memorialize", beneficiary="Asha Rao",
                instructions="Turn it into a memorial page.",
            ),
            DigitalAccount(
                user_id=uid, service="Crypto Wallet", account_identifier="0xDEMO…c0de",
                action="Transfer", beneficiary="Rohan Rao",
                instructions="Recovery phrase is in the fireproof box.",
            ),
            DigitalAccount(
                user_id=uid, service="Old Forum", account_identifier="demo_user_99",
                action="Delete", beneficiary="",
                instructions="Close this account — nothing worth keeping.",
            ),
            DigitalAccount(
                user_id=uid, service="Netflix", account_identifier="demo@gmail.com",
                action="Delete", beneficiary="",
                instructions="Cancel the subscription.",
            ),
        ])
        db.session.commit()

        # --- Trusted contacts -----------------------------------------
        db.session.add_all([
            TrustedContact(user_id=uid, name="Rohan Rao", relationship_="Brother",
                           email="rohan@example.com", phone="9800000003"),
            TrustedContact(user_id=uid, name="Meera Iyer", relationship_="Family friend",
                           email="meera@example.com", phone="9800000004"),
        ])
        db.session.commit()

        # --- Life verification: checked in, healthy -------------------
        # (Simulation only. Nothing is ever released automatically.)
        now = datetime.utcnow()
        db.session.add(LifeVerification(
            user_id=uid,
            last_verified_at=now - timedelta(days=6),
            next_verification_due=now + timedelta(days=24),
            status="OK",
            verification_interval_days=30,
        ))
        db.session.commit()

        # --- Inheritance tasks: all three statuses --------------------
        db.session.add_all([
            Task(user_id=uid, title="Contact the bank",
                 description="Inform HDFC Bank and begin the claim process.",
                 status="Pending"),
            Task(user_id=uid, title="File the insurance claim",
                 description="Submit the LIC claim with the policy schedule.",
                 status="Pending"),
            Task(user_id=uid, title="Check property documents",
                 description="Verify the title deed and registration.",
                 status="In Progress"),
            Task(user_id=uid, title="Review the mutual fund",
                 description="Look over the folio and add a nominee.",
                 status="In Progress"),
            Task(user_id=uid, title="Review digital accounts",
                 description="Go through each account's instructions.",
                 status="Completed"),
            Task(user_id=uid, title="Collect the death certificates",
                 description="Order several certified copies.",
                 status="Completed"),
        ])
        db.session.commit()

        # --- Done -----------------------------------------------------
        print("Demo data seeded successfully.")
        print(f"  Login with: {DEMO_EMAIL} / {DEMO_PASSWORD}")
        print("  6 assets · 3 nominees · 6 will instructions · 3 documents")
        print("  5 digital accounts · 2 trusted contacts · 6 tasks")
        print()
        print('  "Mutual Fund" has no nominee and no will instruction ON PURPOSE,')
        print("  so the Will Checker has real warnings to show.")


if __name__ == "__main__":
    seed(reset="--reset" in sys.argv[1:])
