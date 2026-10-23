"""
Step 28 — Security re-audit (automated part).

Uses Flask's test client against the REAL database with two throwaway
accounts, then deletes them and every file they created. Nobody else's data
is read or changed.

Run with: python security_audit.py      (exit code 0 = everything held)
"""
import glob
import io
import os
import re
import sys

import app as appmod
from models import db, User, Document, WillInstruction

A_EMAIL, B_EMAIL = "audit.a.step28@example.com", "audit.b.step28@example.com"
PASSWORD = "audit-pass-123"
failures = []


def check(name, condition, detail=""):
    print(("[PASS] " if condition else "[FAIL] ") + name + ("" if condition else f" -> {detail}"))
    if not condition:
        failures.append(name)


def csrf(data):
    m = re.search(r'name="csrf_token" value="([^"]+)"', data.decode())
    assert m, "no csrf token on page"
    return m.group(1)


def signup_and_login(email):
    c = appmod.app.test_client()
    tok = csrf(c.get("/register").data)
    c.post("/register", data={"csrf_token": tok, "full_name": "Audit " + email[:7], "email": email,
                              "password": PASSWORD, "confirm_password": PASSWORD})
    tok = csrf(c.get("/login").data)
    c.post("/login", data={"csrf_token": tok, "email": email, "password": PASSWORD})
    return c


def post(c, url, page, **data):
    return c.post(url, data={"csrf_token": csrf(c.get(page).data), **data}, follow_redirects=True)


def cleanup():
    with appmod.app.app_context():
        for email in (A_EMAIL, B_EMAIL):
            u = User.query.filter_by(email=email).first()
            if not u:
                continue
            for d in Document.query.filter_by(user_id=u.id).all():
                p = os.path.join(appmod.UPLOAD_DIR, d.stored_filename)
                if os.path.exists(p):
                    os.remove(p)
            db.session.delete(u)
        db.session.commit()


cleanup()
try:
    # ---- 1. Configuration & static scans ---------------------------------
    src = open("app.py", encoding="utf-8").read()
    check("SECRET_KEY is not hardcoded", not re.search(r'SECRET_KEY\s*=\s*["\']', src))
    check("database path comes from the environment", 'os.environ.get(\n    "DATABASE_PATH"' in src or "DATABASE_PATH" in src and "os.environ" in src)
    check(".env is gitignored", ".env" in open(".gitignore", encoding="utf-8").read().split())

    missing = []
    for path in glob.glob("templates/*.html"):
        text = open(path, encoding="utf-8").read()
        for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", text, re.S | re.I):
            if re.search(r'method=["\']?post', m.group(0)[:300], re.I) and "csrf_token" not in m.group(0):
                missing.append(path)
    check("every POST form in templates carries a CSRF token", not missing, missing)

    # ---- 2. Anonymous visitors -------------------------------------------
    anon = appmod.app.test_client()
    protected = ["/dashboard", "/assets", "/nominees", "/will", "/will/checker", "/documents",
                 "/documents/upload", "/digital-legacy", "/trusted-contacts",
                 "/life-verification", "/tasks", "/documents/1/download", "/documents/1/fingerprint"]
    bad = [u for u in protected if anon.get(u).status_code != 302 or "/login" not in anon.get(u).headers["Location"]]
    check("anonymous visitors are sent to log in everywhere", not bad, bad)

    # ---- 3. Two real users ------------------------------------------------
    a, b = signup_and_login(A_EMAIL), signup_and_login(B_EMAIL)

    check("logging out needs POST (GET is refused)", a.get("/logout").status_code == 405)
    r = a.post("/assets/add", data={"name": "x", "category": "Property"})
    check("POST without a CSRF token is refused", r.status_code == 400, r.status_code)

    # security headers
    h = a.get("/dashboard").headers
    check("security headers are set", h.get("X-Content-Type-Options") == "nosniff"
          and h.get("X-Frame-Options") == "DENY" and "no-store" in (h.get("Cache-Control") or ""), dict(h))

    # weak input
    tok = csrf(anon.get("/register").data)
    anon.post("/register", data={"csrf_token": tok, "full_name": "Short", "email": "short.step28@example.com",
                                 "password": "abc", "confirm_password": "abc"})
    with appmod.app.app_context():
        check("too-short passwords are refused at sign-up", User.query.filter_by(email="short.step28@example.com").first() is None)

    # ---- 4. Cross-user access (IDOR) -------------------------------------
    post(a, "/assets/add", "/assets/add", name="A's House", category="Property", approx_value="100")
    with appmod.app.app_context():
        from models import Asset
        a_asset = Asset.query.filter_by(user_id=User.query.filter_by(email=A_EMAIL).first().id).first()
        a_asset_id = a_asset.id
    check("B cannot open A's asset", b.get(f"/assets/{a_asset_id}/edit").status_code == 404)
    check("B cannot delete A's asset", post(b, f"/assets/{a_asset_id}/delete", "/assets").status_code == 404)

    post(b, "/will/add", "/will/add", asset_id=str(a_asset_id), beneficiary_name="Mallory", instruction_text="steal")
    with appmod.app.app_context():
        b_id = User.query.filter_by(email=B_EMAIL).first().id
        leaked = WillInstruction.query.filter_by(user_id=b_id).first()
        check("B cannot link a will instruction to A's asset", leaked is None)
    post(b, "/will/add", "/will/add", asset_id="not-a-number", beneficiary_name="X", instruction_text="y")
    with appmod.app.app_context():
        check("a junk asset id is refused, not a crash", WillInstruction.query.filter_by(user_id=b_id).first() is None)
    r = post(a, "/assets/add", "/assets/add", name="Bad value", category="Other", approx_value="nan")
    check("a non-numeric asset value is refused, not a crash", r.status_code == 200 and b"plain number" in r.data)

    # ---- 5. Uploads --------------------------------------------------------
    def upload(c, name, content, category="Will"):
        return c.post("/documents/upload", data={
            "csrf_token": csrf(c.get("/documents/upload").data), "category": category,
            "file": (io.BytesIO(content), name)}, content_type="multipart/form-data", follow_redirects=True)

    r = a.post("/documents/upload", data={"csrf_token": csrf(a.get("/documents/upload").data), "category": "Will"},
               content_type="multipart/form-data", follow_redirects=True)
    check("upload with no file is refused kindly", b"choose a file" in r.data.lower())
    check("wrong extension is refused", b"only store pdf" in upload(a, "run.exe", b"MZ").data.lower())
    check("empty .pdf is refused", b"doesn" in upload(a, "empty.pdf", b"").data.lower())
    r = upload(a, "big.pdf", b"%PDF-1.4 " + b"A" * (11 * 1024 * 1024))
    check("oversized upload gets a friendly message", b"too large" in r.data.lower())
    check("path-style filename can't escape", b"safely filed" in upload(a, "../../evil.pdf", b"%PDF-1.4 ok").data.lower())
    with appmod.app.app_context():
        docs = Document.query.filter_by(user_id=User.query.filter_by(email=A_EMAIL).first().id).all()
        doc_id = docs[0].id if docs else None
        check("stored under a random name, never the uploaded one",
              bool(docs) and all(re.fullmatch(r"[0-9a-f]{32}\.pdf", d.stored_filename) for d in docs))
    if doc_id:
        check("B cannot download A's document", b.get(f"/documents/{doc_id}/download").status_code == 404)
        check("B cannot read A's fingerprint", b.get(f"/documents/{doc_id}/fingerprint").status_code == 404)
        check("A can download their own document", a.get(f"/documents/{doc_id}/download").status_code == 200)

    # ---- 5b. Integrity Seal (no wallet needed) -----------------------------
    if doc_id:
        check("B cannot seal A's document", post(b, f"/documents/{doc_id}/seal", "/documents").status_code == 404)
        r = post(a, f"/documents/{doc_id}/seal", "/documents")
        check("A can seal their own document", b"Sealed" in r.data)
        with appmod.app.app_context():
            stored = db.session.get(Document, doc_id).stored_filename
        with open(os.path.join(appmod.UPLOAD_DIR, stored), "ab") as fh:
            fh.write(b"tampered")
        check("changing a sealed file flips its badge to Tampered", b"Tampered" in a.get("/documents").data)

    # ---- 6. Login throttling ----------------------------------------------
    appmod._FAILED_LOGINS.clear()
    t = appmod.app.test_client()
    for _ in range(appmod.LOGIN_MAX_FAILS):
        t.post("/login", data={"csrf_token": csrf(t.get("/login").data), "email": B_EMAIL, "password": "wrong"})
    r = t.post("/login", data={"csrf_token": csrf(t.get("/login").data), "email": B_EMAIL, "password": PASSWORD},
               follow_redirects=True)
    check("after 5 wrong tries even the right password is held back", b"too many" in r.data.lower())
    appmod._FAILED_LOGINS.clear()
    r = t.post("/login", data={"csrf_token": csrf(t.get("/login").data), "email": B_EMAIL, "password": PASSWORD},
               follow_redirects=True)
    check("a normal login still works once the lock clears", b"dashboard" in r.data.lower())
    check("health check answers without logging in", appmod.app.test_client().get("/healthz").data == b"ok")
finally:
    appmod._FAILED_LOGINS.clear()
    cleanup()

print()
if failures:
    print(f"{len(failures)} check(s) FAILED: {failures}")
    sys.exit(1)
print("All security checks passed.")
