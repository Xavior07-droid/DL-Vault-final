"""
Step 5 — Full manual walkthrough / smoke test.

Walks every one of the 11 features in one continuous session, the way a
real user would (register -> login -> touch every feature -> logout),
using Flask's test client against the REAL sqlite database. A dedicated
throwaway account is used so the person's existing data is never
touched. The account and everything it created is deleted at the end.

Run with: python smoke_test.py
Exit code 0 = everything passed. Any AssertionError = a real bug found.
"""
import html
import io
import os
import re
import sys

import app as appmod
from models import db, User

TEST_EMAIL = "smoketest.step5@example.com"
TEST_PASSWORD = "smoketest123"

client = appmod.app.test_client()

results = []


def step(name):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            try:
                fn(*args, **kwargs)
                results.append((name, "PASS", None))
                print(f"[PASS] {name}")
            except Exception as e:
                results.append((name, "FAIL", str(e)))
                print(f"[FAIL] {name} -> {e}")
                raise
        return wrapper
    return decorator


def visible_text(response):
    """Page text with tags stripped AND entities decoded (\u0027 -> ').
    Needed because Jinja escapes apostrophes to &#39; in rendered pages."""
    raw = re.sub(r"<[^>]+>", " ", response.data.decode())
    return re.sub(r"\s+", " ", html.unescape(raw))


def csrf(page):
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.decode())
    assert m, "no csrf token found on page"
    return m.group(1)


# ---------------------------------------------------------------------
# 0. Pre-flight: make sure no leftover account exists from a prior run
# ---------------------------------------------------------------------
with appmod.app.app_context():
    existing = User.query.filter_by(email=TEST_EMAIL).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        print("[setup] removed leftover smoke-test account from a prior run")


# ---------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------
@step("1. Register / login / logout — register")
def test_register():
    r = client.get("/register")
    assert r.status_code == 200
    token = csrf(r.data)
    r = client.post("/register", data={
        "csrf_token": token,
        "full_name": "Smoke Test User",
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "confirm_password": TEST_PASSWORD,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"log in" in r.data.lower() or b"login" in r.data.lower()


@step("1. Register / login / logout — duplicate email is rejected")
def test_register_duplicate():
    r = client.get("/register")
    token = csrf(r.data)
    r = client.post("/register", data={
        "csrf_token": token,
        "full_name": "Duplicate",
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "confirm_password": TEST_PASSWORD,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"already exists" in r.data.lower()


@step("1. Register / login / logout — wrong password rejected")
def test_login_wrong_password():
    r = client.get("/login")
    token = csrf(r.data)
    r = client.post("/login", data={
        "csrf_token": token,
        "email": TEST_EMAIL,
        "password": "wrong-password",
    }, follow_redirects=True)
    assert b"invalid" in r.data.lower()


@step("1. Register / login / logout — correct login reaches dashboard")
def test_login():
    r = client.get("/login")
    token = csrf(r.data)
    r = client.post("/login", data={
        "csrf_token": token,
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Dashboard" in r.data or b"dashboard" in r.data.lower()


@step("1. Register / login / logout — protected page blocked before login is undone by our login above (sanity)")
def test_dashboard_reachable():
    r = client.get("/dashboard")
    assert r.status_code == 200


# ---------------------------------------------------------------------
# 2. Dashboard (revisited after data exists, later in this script)
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# 3. Assets
# ---------------------------------------------------------------------
asset_id = None


@step("3. Assets — add")
def test_asset_add():
    global asset_id
    r = client.get("/assets/add")
    token = csrf(r.data)
    r = client.post("/assets/add", data={
        "csrf_token": token,
        "name": "Mumbai Property",
        "category": "Real Estate",
        "provider": "Self-owned",
        "reference": "PROP-001",
        "approx_value": "5000000",
        "description": "Family flat",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Mumbai Property" in r.data
    with appmod.app.app_context():
        from models import Asset
        a = Asset.query.filter_by(name="Mumbai Property").first()
        assert a is not None
        asset_id = a.id


@step("3. Assets — edit")
def test_asset_edit():
    r = client.get(f"/assets/{asset_id}/edit")
    assert r.status_code == 200
    token = csrf(r.data)
    r = client.post(f"/assets/{asset_id}/edit", data={
        "csrf_token": token,
        "name": "Mumbai Property (Edited)",
        "category": "Real Estate",
        "provider": "Self-owned",
        "reference": "PROP-001",
        "approx_value": "5500000",
        "description": "Family flat, updated value",
    }, follow_redirects=True)
    assert b"Mumbai Property (Edited)" in r.data


# ---------------------------------------------------------------------
# 4. Nominees
# ---------------------------------------------------------------------
nominee_id = None


@step("4. Nominees — add")
def test_nominee_add():
    global nominee_id
    r = client.get("/nominees/add")
    token = csrf(r.data)
    r = client.post("/nominees/add", data={
        "csrf_token": token,
        "name": "Mother",
        "relationship": "Mother",
        "email": "mother@example.com",
        "phone": "9999999999",
    }, follow_redirects=True)
    assert b"Mother" in r.data
    with appmod.app.app_context():
        from models import Nominee
        n = Nominee.query.filter_by(name="Mother").first()
        assert n is not None
        nominee_id = n.id


@step("4. Nominees — edit")
def test_nominee_edit():
    r = client.get(f"/nominees/{nominee_id}/edit")
    token = csrf(r.data)
    r = client.post(f"/nominees/{nominee_id}/edit", data={
        "csrf_token": token,
        "name": "Mother (Primary)",
        "relationship": "Mother",
        "email": "mother@example.com",
        "phone": "9999999999",
    }, follow_redirects=True)
    assert b"Mother (Primary)" in r.data


# ---------------------------------------------------------------------
# 5. Assign nominee to asset
# ---------------------------------------------------------------------
@step("5. Assign nominee to asset")
def test_assign_nominee():
    r = client.get(f"/assets/{asset_id}/assign-nominee")
    assert r.status_code == 200
    token = csrf(r.data)
    r = client.post(f"/assets/{asset_id}/assign-nominee", data={
        "csrf_token": token,
        "nominee_id": str(nominee_id),
    }, follow_redirects=True)
    assert b"Mother (Primary)" in r.data

    r = client.get("/assets")
    assert b"Mother (Primary)" in r.data  # shows on the assets list too


# ---------------------------------------------------------------------
# 6. Will instructions
# ---------------------------------------------------------------------
will_id = None


@step("6. Will instructions — add tied to the asset + beneficiary")
def test_will_add():
    global will_id
    r = client.get("/will/add")
    token = csrf(r.data)
    r = client.post("/will/add", data={
        "csrf_token": token,
        "asset_id": str(asset_id),
        "beneficiary_name": "Mother (Primary)",
        "instruction_text": "Transfer property to mother",
    }, follow_redirects=True)
    assert b"Transfer property to mother" in r.data
    with appmod.app.app_context():
        from models import WillInstruction
        w = WillInstruction.query.filter_by(
            instruction_text="Transfer property to mother"
        ).first()
        assert w is not None
        will_id = w.id


@step("6. Will instructions — add a second one, then edit it to drop its beneficiary")
def test_will_add_incomplete():
    # The add form correctly REFUSES a blank beneficiary, so the only way
    # to reach the checker's "no beneficiary" rule through the UI is to
    # save a valid instruction and then blank the beneficiary on edit.
    r = client.get("/will/add")
    token = csrf(r.data)
    r = client.post("/will/add", data={
        "csrf_token": token,
        "asset_id": "",
        "beneficiary_name": "Temp Person",
        "instruction_text": "General note to be edited",
    }, follow_redirects=True)
    assert b"General note to be edited" in r.data

    with appmod.app.app_context():
        from models import WillInstruction
        w = WillInstruction.query.filter_by(
            instruction_text="General note to be edited"
        ).first()
        assert w is not None
        wid = w.id

    r = client.get(f"/will/{wid}/edit")
    token = csrf(r.data)
    r = client.post(f"/will/{wid}/edit", data={
        "csrf_token": token,
        "asset_id": "",
        "beneficiary_name": "",
        "instruction_text": "General note to be edited",
    }, follow_redirects=True)
    assert r.status_code == 200


# ---------------------------------------------------------------------
# 7. Will Checker
# ---------------------------------------------------------------------
@step("7. Will Checker — asset with instruction+nominee shows PASS, orphan flagged")
def test_will_checker():
    r = client.get("/will/checker")
    assert r.status_code == 200
    # our covered asset should PASS the "has instruction" and "has nominee" rules
    assert b"Mumbai Property (Edited)" in r.data
    assert b"PASS" in r.data
    # the beneficiary-less instruction must be flagged by Rule 4
    assert b"WARNING" in r.data


# ---------------------------------------------------------------------
# 8. Documents
# ---------------------------------------------------------------------
document_id = None
stored_filename = None


@step("8. Documents — upload")
def test_document_upload():
    global document_id, stored_filename
    r = client.get("/documents/upload")
    token = csrf(r.data)
    data = {
        "csrf_token": token,
        "category": "Will",
        "description": "Smoke test document",
        "file": (io.BytesIO(b"%PDF-1.4 fake content for smoke test"), "smoke_test.pdf"),
    }
    r = client.post("/documents/upload", data=data, content_type="multipart/form-data",
                     follow_redirects=True)
    assert b"smoke_test.pdf" in r.data
    with appmod.app.app_context():
        from models import Document
        d = Document.query.filter_by(original_filename="smoke_test.pdf").first()
        assert d is not None
        document_id = d.id
        stored_filename = d.stored_filename


@step("8. Documents — reject disallowed extension")
def test_document_upload_rejected_extension():
    r = client.get("/documents/upload")
    token = csrf(r.data)
    data = {
        "csrf_token": token,
        "category": "Will",
        "description": "Should be rejected",
        "file": (io.BytesIO(b"not allowed"), "malware.exe"),
    }
    r = client.post("/documents/upload", data=data, content_type="multipart/form-data",
                     follow_redirects=True)
    assert b"only pdf" in r.data.lower() or b"not allowed" in r.data.lower() or b"jpg" in r.data.lower()


@step("8. Documents — executable renamed .pdf is rejected by content, nothing stored")
def test_document_fake_pdf_rejected():
    before = set(os.listdir(appmod.UPLOAD_DIR))
    r = client.get("/documents/upload")
    token = csrf(r.data)
    r = client.post("/documents/upload", data={
        "csrf_token": token, "category": "Will", "description": "",
        "file": (io.BytesIO(b"MZ\x90\x00 pretend windows executable"), "invoice.pdf"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert "doesn't look like a real PDF" in visible_text(r)
    assert set(os.listdir(appmod.UPLOAD_DIR)) == before, "rejected file was written to disk"
    with appmod.app.app_context():
        from models import Document
        assert Document.query.filter_by(original_filename="invoice.pdf").count() == 0


@step("8. Documents — mismatched type (PDF bytes named .png) is rejected")
def test_document_mismatched_type_rejected():
    r = client.get("/documents/upload")
    token = csrf(r.data)
    r = client.post("/documents/upload", data={
        "csrf_token": token, "category": "Will", "description": "",
        "file": (io.BytesIO(b"%PDF-1.4 real pdf bytes"), "photo.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert "doesn't look like a real PNG" in visible_text(r)


@step("8. Documents — oversize upload shows a friendly message, not a raw 413")
def test_document_oversize_friendly():
    r = client.get("/documents/upload")
    token = csrf(r.data)
    big = io.BytesIO(b"%PDF-1.4 " + b"A" * (11 * 1024 * 1024))
    r = client.post("/documents/upload", data={
        "csrf_token": token, "category": "Will", "description": "",
        "file": (big, "big.pdf"),
    }, content_type="multipart/form-data", follow_redirects=True)
    text = visible_text(r)
    assert r.status_code == 200
    assert "too large" in text and "10 MB" in text
    assert "Request Entity Too Large" not in text


@step("8. Documents — a forged category outside the list is rejected")
def test_document_forged_category_rejected():
    r = client.get("/documents/upload")
    token = csrf(r.data)
    r = client.post("/documents/upload", data={
        "csrf_token": token, "category": "<script>alert(1)</script>", "description": "",
        "file": (io.BytesIO(b"%PDF-1.4 ok"), "forged.pdf"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert "choose a category" in visible_text(r).lower()
    with appmod.app.app_context():
        from models import Document
        assert Document.query.filter_by(original_filename="forged.pdf").count() == 0



@step("8. Documents — opting in saves a correct fingerprint; opting out saves none; delete removes both")
def test_document_notarize_optin():
    import hashlib
    import os

    content = b"%PDF-1.4 notarize me " + os.urandom(64)
    r = client.get("/documents/upload")
    token = csrf(r.data)
    r = client.post("/documents/upload", data={
        "csrf_token": token, "category": "Will", "description": "",
        "notarize": "on",
        "file": (io.BytesIO(content), "notarized.pdf"),
    }, content_type="multipart/form-data", follow_redirects=True)
    text = visible_text(r)
    assert "fingerprint is saved" in text, "opt-in confirmation message missing"
    assert "Ready to notarize" in text, "pending badge missing from the documents list"
    assert "Not notarized" in text, "plain documents should show a quiet Not notarized badge"

    with appmod.app.app_context():
        from models import Document
        d = Document.query.filter_by(original_filename="notarized.pdf").first()
        assert d is not None and d.proof is not None, "no proof row for an opted-in document"
        assert d.proof.sha256_hash == hashlib.sha256(content).hexdigest(), "fingerprint is wrong"
        assert d.proof.status == "PENDING"
        assert d.proof.ipfs_cid is None, "nothing should be sent to IPFS"
        # The earlier plain upload never ticked the box, so it must have no proof.
        plain = Document.query.filter_by(id=document_id).first()
        assert plain is not None and plain.proof is None, "opt-out document got a proof anyway"
        doc_id, stored, proof_id = d.id, d.stored_filename, d.proof.id

    # Deleting the document removes the file AND its fingerprint row.
    r = client.get("/documents")
    token = csrf(r.data)
    client.post(f"/documents/{doc_id}/delete", data={"csrf_token": token}, follow_redirects=True)
    assert not os.path.exists(os.path.join(appmod.UPLOAD_DIR, stored)), "file left on disk"
    with appmod.app.app_context():
        from models import DocumentProof
        assert db.session.get(DocumentProof, proof_id) is None, "proof row left behind"


@step("8. Documents — notarization endpoints: fingerprint, tamper detection, server-side receipt checks")
def test_document_notarization_endpoints():
    import hashlib
    import os
    import urllib.error
    from models import Document

    content = b"%PDF-1.4 endpoints " + os.urandom(64)
    fhash = hashlib.sha256(content).hexdigest()
    token = csrf(client.get("/documents/upload").data)
    client.post("/documents/upload", data={
        "csrf_token": token, "category": "Will", "description": "", "notarize": "on",
        "file": (io.BytesIO(content), "proof.pdf"),
    }, content_type="multipart/form-data", follow_redirects=True)
    with appmod.app.app_context():
        d = Document.query.filter_by(original_filename="proof.pdf").first()
        assert d is not None
        doc_id, stored = d.id, d.stored_filename
    path = os.path.join(appmod.UPLOAD_DIR, stored)

    def proof_now():
        with appmod.app.app_context():
            p = Document.query.get(doc_id).proof
            return {"status": p.status, "tx": p.tx_hash, "wallet": p.wallet_address,
                    "network": p.network, "at": p.notarized_at}

    def confirm(tx, headers=True):
        h = {"X-CSRFToken": csrf(client.get("/documents").data)} if headers else {}
        return client.post(f"/documents/{doc_id}/notarize/confirm", json={"tx_hash": tx}, headers=h)

    CONTRACT = "0x" + "cd" * 20
    WALLET = "0x" + "ab" * 20
    TX = "0x" + "12" * 32

    def receipt(**over):
        r = {"status": "0x1", "to": CONTRACT, "from": WALLET,
             "logs": [{"address": CONTRACT, "topics": ["0x" + "11" * 32, "0x" + fhash]}]}
        r.update(over)
        return r

    saved_contract, saved_fetch = appmod.NOTARIZATION_CONTRACT_ADDRESS, appmod.fetch_tx_receipt
    try:
        # --- fingerprint endpoint -----------------------------------------
        r = client.get(f"/documents/{doc_id}/fingerprint")
        j = r.get_json()
        assert r.status_code == 200 and j["ok"], "fingerprint endpoint failed"
        assert j["current_hash"] == fhash and j["stored_hash"] == fhash and j["status"] == "PENDING"
        j2 = client.get(f"/documents/{document_id}/fingerprint").get_json()
        assert j2["stored_hash"] is None and j2["status"] is None, "opt-out doc should have no proof"
        assert client.get("/documents/999999/fingerprint").status_code == 404, "unknown id should 404"
        anon = appmod.app.test_client()
        r = anon.get(f"/documents/{doc_id}/fingerprint")
        assert r.status_code == 302 and "/login" in r.headers["Location"], "fingerprint must need login"

        # --- confirm: refuses while notarization is switched off ----------
        appmod.NOTARIZATION_CONTRACT_ADDRESS = ""
        r = confirm(TX)
        assert r.status_code == 400 and "switched on" in r.get_json()["error"]

        appmod.NOTARIZATION_CONTRACT_ADDRESS = CONTRACT
        appmod.fetch_tx_receipt = lambda tx: receipt()

        # --- confirm: bad input, missing CSRF, tampered file ---------------
        r = confirm("not-a-hash")
        assert r.status_code == 400 and not r.get_json()["ok"], "bad tx hash should be refused"
        r = confirm(TX, headers=False)
        assert r.status_code == 400 and proof_now()["status"] == "PENDING", "CSRF header must be required"

        original = open(path, "rb").read()
        with open(path, "ab") as fh:
            fh.write(b"X")                                    # tamper with the stored file
        j = client.get(f"/documents/{doc_id}/fingerprint").get_json()
        assert j["current_hash"] != j["stored_hash"], "tampering must change the fingerprint"
        r = confirm(TX)
        assert r.status_code == 409 and proof_now()["status"] == "PENDING", "must refuse a changed file"
        with open(path, "wb") as fh:
            fh.write(original)                                # restore it
        assert client.get(f"/documents/{doc_id}/fingerprint").get_json()["current_hash"] == fhash

        # --- confirm: every way a receipt can be wrong ---------------------
        appmod.fetch_tx_receipt = lambda tx: receipt(logs=[{"address": CONTRACT, "topics": ["0x1", "0x" + "aa" * 32]}])
        r = confirm(TX)
        assert r.status_code == 400 and proof_now()["status"] == "PENDING", "other document's receipt accepted!"

        appmod.fetch_tx_receipt = lambda tx: receipt(to="0x" + "99" * 20)
        assert confirm(TX).status_code == 400 and proof_now()["status"] == "PENDING", "wrong contract accepted!"

        appmod.fetch_tx_receipt = lambda tx: None
        r = confirm(TX)
        assert r.status_code == 202 and r.get_json()["pending"] and proof_now()["status"] == "PENDING"

        def unreachable(tx):
            raise urllib.error.URLError("no network")
        appmod.fetch_tx_receipt = unreachable
        r = confirm(TX)
        assert r.status_code == 502 and proof_now()["status"] == "PENDING", "network trouble must not change state"

        appmod.fetch_tx_receipt = lambda tx: receipt(status="0x0")
        r = confirm(TX)
        assert r.status_code == 400 and proof_now()["status"] == "FAILED", "a reverted tx should mark FAILED"

        # --- confirm: the real thing (and retry after FAILED) --------------
        appmod.fetch_tx_receipt = lambda tx: receipt()
        r = confirm(TX)
        assert r.status_code == 200 and r.get_json()["ok"], "valid receipt was rejected"
        p = proof_now()
        assert p["status"] == "NOTARIZED" and p["tx"] == TX
        assert p["wallet"] == WALLET, "wallet must come from the receipt"
        assert p["network"] == "polygon-amoy-testnet" and p["at"] is not None
        assert "Notarized" in visible_text(client.get("/documents")), "badge missing after notarization"

        r = confirm(TX)
        assert r.status_code == 200 and r.get_json().get("already"), "repeat confirm should be a no-op"
    finally:
        appmod.NOTARIZATION_CONTRACT_ADDRESS = saved_contract
        appmod.fetch_tx_receipt = saved_fetch
        token = csrf(client.get("/documents").data)
        client.post(f"/documents/{doc_id}/delete", data={"csrf_token": token}, follow_redirects=True)


@step("8. Documents — download")
def test_document_download():
    r = client.get(f"/documents/{document_id}/download")
    assert r.status_code == 200


# ---------------------------------------------------------------------
# 9. Digital legacy accounts
# ---------------------------------------------------------------------
digital_account_id = None


@step("9. Digital legacy — add")
def test_digital_account_add():
    global digital_account_id
    r = client.get("/digital-legacy/add")
    token = csrf(r.data)
    r = client.post("/digital-legacy/add", data={
        "csrf_token": token,
        "service": "Gmail",
        "account_identifier": "smoketest@gmail.com",
        "action": "Memorialize",
        "beneficiary": "Mother (Primary)",
        "instructions": "Keep photos, close the rest",
    }, follow_redirects=True)
    assert b"Gmail" in r.data
    with appmod.app.app_context():
        from models import DigitalAccount
        acc = DigitalAccount.query.filter_by(service="Gmail").first()
        assert acc is not None
        digital_account_id = acc.id


@step("9. Digital legacy — edit")
def test_digital_account_edit():
    r = client.get(f"/digital-legacy/{digital_account_id}/edit")
    token = csrf(r.data)
    r = client.post(f"/digital-legacy/{digital_account_id}/edit", data={
        "csrf_token": token,
        "service": "Gmail (Personal)",
        "account_identifier": "smoketest@gmail.com",
        "action": "Transfer",
        "beneficiary": "Mother (Primary)",
        "instructions": "Transfer ownership",
    }, follow_redirects=True)
    assert b"Gmail (Personal)" in r.data


# ---------------------------------------------------------------------
# 10. Trusted contacts
# ---------------------------------------------------------------------
trusted_contact_id = None


@step("10. Trusted contacts — add")
def test_trusted_contact_add():
    global trusted_contact_id
    r = client.get("/trusted-contacts/add")
    token = csrf(r.data)
    r = client.post("/trusted-contacts/add", data={
        "csrf_token": token,
        "name": "Family Lawyer",
        "relationship": "Lawyer",
        "email": "lawyer@example.com",
        "phone": "8888888888",
    }, follow_redirects=True)
    assert b"Family Lawyer" in r.data
    with appmod.app.app_context():
        from models import TrustedContact
        c = TrustedContact.query.filter_by(name="Family Lawyer").first()
        assert c is not None
        trusted_contact_id = c.id


@step("10. Trusted contacts — edit")
def test_trusted_contact_edit():
    r = client.get(f"/trusted-contacts/{trusted_contact_id}/edit")
    token = csrf(r.data)
    r = client.post(f"/trusted-contacts/{trusted_contact_id}/edit", data={
        "csrf_token": token,
        "name": "Family Lawyer (Primary)",
        "relationship": "Lawyer",
        "email": "lawyer@example.com",
        "phone": "8888888888",
    }, follow_redirects=True)
    assert b"Family Lawyer (Primary)" in r.data


# ---------------------------------------------------------------------
# 11. Life verification
# ---------------------------------------------------------------------
@step("11. Life verification — confirm alive")
def test_life_verification_confirm():
    r = client.get("/life-verification")
    assert r.status_code == 200
    token = csrf(r.data)
    r = client.post("/life-verification/confirm", data={"csrf_token": token},
                     follow_redirects=True)
    assert r.status_code == 200
    # Step 19: the page speaks in plain language, not raw status constants.
    assert b"all checked in" in r.data, "checked-in state not shown after confirming"
    assert b"VERIFICATION_REQUIRED" not in r.data, "raw status constant leaked to the user"


@step("11. Life verification — simulate missed check-in never auto-releases data")
def test_life_verification_simulate_missed():
    r = client.get("/life-verification")
    token = csrf(r.data)
    r = client.post("/life-verification/simulate-missed", data={"csrf_token": token},
                     follow_redirects=True)
    assert b"check-in is overdue" in r.data, "overdue state not shown after simulating a miss"
    assert b"VERIFICATION_REQUIRED" not in r.data, "raw status constant leaked to the user"
    # ...and the stored status really did flip, even though the UI is friendly
    with appmod.app.app_context():
        from models import LifeVerification
        u = User.query.filter_by(email=TEST_EMAIL).first()
        rec = LifeVerification.query.filter_by(user_id=u.id).first()
        assert rec.status == "VERIFICATION_REQUIRED", "status did not flip in the database"
    # critically: our asset/document/etc. must still all exist untouched
    r = client.get("/assets")
    assert b"Mumbai Property (Edited)" in r.data


# ---------------------------------------------------------------------
# 12. Inheritance tasks
# ---------------------------------------------------------------------
task_id = None


@step("12. Tasks — add")
def test_task_add():
    global task_id
    r = client.get("/tasks/add")
    token = csrf(r.data)
    r = client.post("/tasks/add", data={
        "csrf_token": token,
        "title": "Notify bank of estate status",
        "description": "Call the bank branch",
        "status": "Pending",
    }, follow_redirects=True)
    assert b"Notify bank of estate status" in r.data
    with appmod.app.app_context():
        from models import Task
        t = Task.query.filter_by(title="Notify bank of estate status").first()
        assert t is not None
        task_id = t.id


@step("12. Tasks — quick status change")
def test_task_status_change():
    r = client.get("/tasks")
    token = csrf(r.data)
    r = client.post(f"/tasks/{task_id}/status", data={
        "csrf_token": token,
        "status": "In Progress",
    }, follow_redirects=True)
    assert r.status_code == 200
    with appmod.app.app_context():
        from models import Task
        t = db.session.get(Task, task_id)
        assert t.status == "In Progress"


# ---------------------------------------------------------------------
# 13. Dashboard reflects everything created above
# ---------------------------------------------------------------------
@step("2/13. Dashboard reflects real data after every feature has been used")
def test_dashboard_reflects_data():
    r = client.get("/dashboard")
    assert r.status_code == 200
    # Not asserting exact copy (design changes later in the plan) — just
    # that the dashboard renders successfully with data present and
    # doesn't 500.


# ---------------------------------------------------------------------
# Nav bar cross-links (every feature reachable from nav on every page)
# ---------------------------------------------------------------------
@step("13. Every feature reachable from the nav bar")
def test_nav_links():
    r = client.get("/dashboard")
    html = r.data.decode()
    for path in [
        "/dashboard", "/assets", "/nominees", "/will", "/will/checker",
        "/documents", "/digital-legacy", "/trusted-contacts",
        "/life-verification", "/tasks",
    ]:
        assert path in html, f"{path} not linked from nav"

@step("12. Tasks — edit changes title, description and status")
def test_task_edit():
    r = client.get(f"/tasks/{task_id}/edit")
    assert r.status_code == 200
    assert b"<textarea" in r.data and b">None<" not in r.data, "edit form shows literal 'None'"
    token = csrf(r.data)
    client.post(f"/tasks/{task_id}/edit", data={
        "csrf_token": token,
        "title": "Notify bank of estate status (edited)",
        "description": "",
        "status": "Pending",
    }, follow_redirects=True)
    with appmod.app.app_context():
        from models import Task
        t = db.session.get(Task, task_id)
        assert t.title == "Notify bank of estate status (edited)"
        assert t.status == "Pending"


@step("12. Tasks — forged status is ignored, existing status is kept")
def test_task_forged_status():
    r = client.get("/tasks")
    token = csrf(r.data)
    client.post(f"/tasks/{task_id}/status", data={"csrf_token": token, "status": "Hacked"})
    client.post(f"/tasks/{task_id}/edit", data={
        "csrf_token": token, "title": "Notify bank of estate status (edited)",
        "description": "", "status": "<script>"})
    with appmod.app.app_context():
        from models import Task
        assert db.session.get(Task, task_id).status == "Pending"


@step("12. Tasks — page shows progress, friendly wording, and icon+text status")
def test_task_page_display():
    r = client.get("/tasks")
    page = r.get_data(as_text=True)
    assert "0 of 1 done" in page, "progress summary missing or wrong"
    assert 'role="progressbar"' in page
    assert "No tasks yet" not in page
    # every status control is a real button (works without JavaScript)
    assert page.count('name="status" value=') >= 3
    # completing it flips the heading to the all-done message
    token = csrf(r.data)
    client.post(f"/tasks/{task_id}/status", data={"csrf_token": token, "status": "Completed"})
    page = client.get("/tasks").get_data(as_text=True)
    assert "Everything" in page and "100%" in page
    assert "task-done" in page
    # put it back so the cleanup step behaves exactly as before
    token = csrf(client.get("/tasks").data)
    client.post(f"/tasks/{task_id}/status", data={"csrf_token": token, "status": "Pending"})



# ---------------------------------------------------------------------
# Cleanup: delete everything created, then remove the test account
# ---------------------------------------------------------------------
@step("Cleanup — delete task")
def test_cleanup_task():
    r = client.get("/tasks")
    token = csrf(r.data)
    client.post(f"/tasks/{task_id}/delete", data={"csrf_token": token}, follow_redirects=True)


@step("Cleanup — delete trusted contact")
def test_cleanup_trusted_contact():
    r = client.get("/trusted-contacts")
    token = csrf(r.data)
    client.post(f"/trusted-contacts/{trusted_contact_id}/delete", data={"csrf_token": token},
                follow_redirects=True)


@step("Cleanup — delete digital account")
def test_cleanup_digital_account():
    r = client.get("/digital-legacy")
    token = csrf(r.data)
    client.post(f"/digital-legacy/{digital_account_id}/delete", data={"csrf_token": token},
                follow_redirects=True)


@step("Cleanup — delete document (and confirm file removed from disk)")
def test_cleanup_document():
    import os
    r = client.get("/documents")
    token = csrf(r.data)
    client.post(f"/documents/{document_id}/delete", data={"csrf_token": token},
                follow_redirects=True)
    assert not os.path.exists(os.path.join(appmod.UPLOAD_DIR, stored_filename))


@step("Cleanup — delete will instructions")
def test_cleanup_will():
    with appmod.app.app_context():
        from models import WillInstruction, User
        user = User.query.filter_by(email=TEST_EMAIL).first()
        instructions = WillInstruction.query.filter_by(user_id=user.id).all()
    r = client.get("/will")
    token = csrf(r.data)
    for w in instructions:
        client.post(f"/will/{w.id}/delete", data={"csrf_token": token}, follow_redirects=True)


@step("Cleanup — remove nominee from asset, then delete nominee and asset")
def test_cleanup_asset_nominee():
    r = client.get(f"/assets/{asset_id}/assign-nominee")
    token = csrf(r.data)
    client.post(f"/assets/{asset_id}/remove-nominee/{nominee_id}", data={"csrf_token": token},
                follow_redirects=True)

    r = client.get("/nominees")
    token = csrf(r.data)
    client.post(f"/nominees/{nominee_id}/delete", data={"csrf_token": token}, follow_redirects=True)

    r = client.get("/assets")
    token = csrf(r.data)
    client.post(f"/assets/{asset_id}/delete", data={"csrf_token": token}, follow_redirects=True)


@step("Cleanup — logout, then delete the smoke-test account entirely")
def test_cleanup_account():
    page = client.get("/dashboard")
    client.post("/logout", data={"csrf_token": csrf(page.data)}, follow_redirects=True)
    with appmod.app.app_context():
        user = User.query.filter_by(email=TEST_EMAIL).first()
        if user:
            db.session.delete(user)
            db.session.commit()
        # verify fully gone
        assert User.query.filter_by(email=TEST_EMAIL).first() is None


# ---------------------------------------------------------------------
# Run everything in order
# ---------------------------------------------------------------------
if __name__ == "__main__":
    fns = [
        test_register,
        test_register_duplicate,
        test_login_wrong_password,
        test_login,
        test_dashboard_reachable,
        test_asset_add,
        test_asset_edit,
        test_nominee_add,
        test_nominee_edit,
        test_assign_nominee,
        test_will_add,
        test_will_add_incomplete,
        test_will_checker,
        test_document_upload,
        test_document_upload_rejected_extension,
        test_document_fake_pdf_rejected,
        test_document_mismatched_type_rejected,
        test_document_oversize_friendly,
        test_document_forged_category_rejected,
        test_document_notarize_optin,
        test_document_notarization_endpoints,
        test_document_download,
        test_digital_account_add,
        test_digital_account_edit,
        test_trusted_contact_add,
        test_trusted_contact_edit,
        test_life_verification_confirm,
        test_life_verification_simulate_missed,
        test_task_add,
        test_task_status_change,
        test_task_edit,
        test_task_forged_status,
        test_task_page_display,
        test_dashboard_reflects_data,
        test_nav_links,
        test_cleanup_task,
        test_cleanup_trusted_contact,
        test_cleanup_digital_account,
        test_cleanup_document,
        test_cleanup_will,
        test_cleanup_asset_nominee,
        test_cleanup_account,
    ]

    failed = False
    for fn in fns:
        try:
            fn()
        except Exception:
            failed = True
            # keep going so we get a full picture, but remember it failed
            continue

    print()
    print("=" * 60)
    passed = sum(1 for _, status, _ in results if status == "PASS")
    total = len(results)
    print(f"{passed}/{total} steps passed")
    if failed:
        print("SOME STEPS FAILED — see [FAIL] lines above")
        sys.exit(1)
    else:
        print("ALL STEPS PASSED")
        sys.exit(0)
