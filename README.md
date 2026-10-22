# Digital Legacy Vault (Steps 1–30)

A working Flask prototype for the Digital Legacy Vault & Inheritance
Management System. All 14 build steps are implemented:

1. Project setup
2. User registration / login / logout
3. Dashboard
4. Asset management (add / view / edit / delete)
5. Nominee management (add / view / edit / delete, assign to assets)
6. Will / Inheritance instructions (add / view / edit / delete)
7. Will Checker (rule-based, no AI)
8. Document Management (upload / view / download / delete — PDF, JPG, JPEG, PNG)
9. Digital Legacy (digital accounts: add / view / edit / delete)
10. Trusted Contact (add / view / edit / delete)
11. Life Verification (simulation only — never auto-releases anything)
12. Inheritance Tasks (add / view / edit / delete, quick status change)
13. Everything connected via the dashboard and nav bar
14. Demo data seeding (`seed_demo.py`)

## Run it locally

```bash
cd digital-legacy-vault

# create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

The SQLite database is created automatically at
`database/legacy_vault.db` the first time you run the app.

## Try it out — fastest way (with demo data)

```bash
python seed_demo.py
python app.py
```

Log in with:
- **Email:** demo@vault.local
- **Password:** demo1234

This gives you a fully populated vault that touches every feature:
6 assets, 3 nominees, 6 will instructions, 3 documents (real, downloadable
files; one has a notarization fingerprint ready), 5 digital accounts covering all four actions, 2 trusted contacts,
a checked-in life-verification record, and 6 inheritance tasks across all
three statuses.

One asset ("Mutual Fund") is intentionally left without a nominee or will
instruction — open **Will → Checker** to see it flagged as a WARNING
(completeness lands around 92%).

To wipe the demo account and rebuild it from scratch:

```bash
python seed_demo.py --reset
```

`--reset` only ever touches the demo account (`demo@vault.local`) and the
files it owns — no other user's data is read or changed.

## Optional: blockchain document notarization

The vault is fully usable without this. If you want to notarize documents on the
Polygon Amoy test network, follow [`BLOCKCHAIN_SETUP.md`](BLOCKCHAIN_SETUP.md)
to create a wallet and get free test tokens, then confirm it with:

```bash
python check_wallet_setup.py --online
```

Never put a seed phrase or private key in this project — only your public
wallet address is ever needed.

### Notarizing documents (optional)

Tick **Notarize this document** when uploading, then use **Notarize** and
**Verify** on the Documents page. Only a fingerprint is recorded on the
blockchain — your files stay private. Setup is in
[`CONTRACT_DEPLOY.md`](CONTRACT_DEPLOY.md) (Part 4 covers `python vendor_ethers.py`).
Quick self-checks that need no wallet: `node check_notarize_js.js`,
`node check_notarize_flow.js`, `python check_contract_abi.py`.

### Smart contract (optional)

The notarization contract lives in `contracts/DocumentNotary.sol`. You can
compile and test it for free in your browser with no wallet — see
[`CONTRACT_DEPLOY.md`](CONTRACT_DEPLOY.md). `python check_contract_abi.py`
confirms the saved ABI matches the contract source.

## Try it out — manual walkthrough (no seed data)

1. Register a new account.
2. Log in — you'll land on the Dashboard.
3. Add a couple of Assets (e.g. "Mumbai Property", "Bank Account").
4. Add a couple of Nominees (e.g. "Mother", "Brother").
5. From the Assets page, click **Nominees** on an asset to assign one.
6. Go to **Will** and add an inheritance instruction, e.g.
   Asset: Mumbai Property, Beneficiary: Mother,
   Instruction: "Transfer property to mother".
7. Open **Will → Checker** to see PASS/WARNING results.
8. Upload a document under **Documents**.
9. Add a digital account under **Digital Legacy**.
10. Add a person under **Trusted Contact**.
11. Open **Life Verification** — click "Confirm I Am Alive", then try
    "Simulate Missed Verification" to see the VERIFICATION_REQUIRED
    state (nothing is ever auto-released).
12. Add a task under **Inheritance Tasks** and change its status.
13. Logout from the top-right menu.

## Notes on scope

This is an intentionally lean prototype:
- No email sending, no real identity verification, no payment/legal
  integrations — Life Verification is a UI simulation only.
- Passwords are hashed with Werkzeug's `generate_password_hash`, but
  the Flask `SECRET_KEY` in `app.py` is a placeholder — change it
  before any real deployment.
- Single SQLite file, no migrations tooling (`db.create_all()` runs
  on startup).


## Step 26 — Document trust badges

Every document on the Documents page carries a small status badge (icon + words, never colour alone):

| Badge | Meaning |
|---|---|
| Not notarized | Never notarized (the normal state; notarizing is optional) |
| Ready to notarize | Fingerprint saved, not yet recorded on the blockchain |
| Notarized | Recorded on the blockchain; press **Verify** to check the file |
| Verified | Verify read the blockchain and the file matches the record |
| Tampered | The file no longer matches its fingerprint (also flagged on page load) |
| File missing / Couldn't confirm | Cautions — never shown as a pass |

Only the Verify button, which reads the blockchain, can produce **Verified**.

## Step 27 — Microcopy pass

Flash messages, empty states, auth pages and the landing page were rewritten in a warmer voice.
Wording the smoke test depends on was kept.

## Step 28 — Security re-audit

Run `python security_audit.py` (uses two throwaway accounts and cleans up after itself).

Fixed in this step:
- **Cross-user leak:** a will instruction could be linked to *another user's* asset id (the asset's name then appeared on the page). Asset ids from forms are now checked against the logged-in user.
- **Crashes on bad input:** a non-numeric asset value or asset id caused a server error; both are now refused with a friendly message. Negative, NaN and absurd values are rejected.
- **Edit forms** now enforce the same required fields as the add forms; digital-account actions are checked against the allowed list.
- **Logout is POST + CSRF** (it was a plain link).
- **Sign-up** requires a plausible email and a password of at least 8 characters.
- **Headers:** `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Cache-Control: no-store` for logged-in pages.

Not done (noted for deployment): login rate limiting, and a Content-Security-Policy (the pages use a few inline scripts).

## Step 29 — Mobile & cross-browser pass

Checked by reading the CSS and markup (no real devices), then fixed:
- **Closed mobile menu was still reachable by keyboard and screen readers** — it is now truly hidden until opened, closes with Escape, and scrolls if a short screen can't fit it.
- **iOS Safari zoom-on-focus** — form fields are 16px on phones.
- **Tap targets** — buttons and nav links are at least 44px tall on touch screens.
- **Stacked document cards** — names and notarization messages are left-aligned and wrap long filenames; action buttons wrap.
- **Tablet widths (641–900px)** — tighter table cells so five-column tables don't overflow.
- Address-bar-safe page height (`100dvh`), `theme-color` for the browser toolbar, and an images/icons never-overflow rule.

Please still do a real-device walkthrough: Chrome and Safari on a phone, plus desktop Chrome/Firefox/Edge, covering each page, the menu, an upload, and Verify with MetaMask.

## Step 30 — Deployment

See [`DEPLOYMENT.md`](DEPLOYMENT.md): Render blueprint (`render.yaml`), `Procfile`, `start.sh`
(gunicorn, one worker), `/healthz`, a login throttle (5 wrong tries → 15-minute hold), the final
walkthrough checklist, and an honest note on free-tier storage.

## Integrity Seal (no wallet, no crypto)

Documents can be **sealed** instead of (or before) being notarized on the blockchain. A seal saves the
file's SHA-256 fingerprint privately in the vault's own database — nothing leaves the vault and no wallet
or third party is involved. Every time the Documents page opens, each sealed file is re-checked: it shows
**Sealed** while it matches and **Tampered** if even one byte has changed. Plain documents get a **Seal**
button, and the upload form offers "Seal this document" whenever blockchain notarization is not switched on.

A seal protects against the *file* being altered. It is not an independent public timestamp — that is what the
optional blockchain notarization adds.
