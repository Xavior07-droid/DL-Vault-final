# Deploying the Vault (Step 30)

Everything below uses free tiers. Hosting needs **your** account, so these steps are for you to run.

## Read this first: free hosts forget things
Free web hosts (Render's free plan included) wipe the app's disk on every redeploy and
after a sleep/restart. The SQLite database and uploaded files live on that disk, so:
- **Use the deployed site for a demo, not for real documents.**
- `SEED_DEMO=true` re-creates the demo account (`demo@vault.local` / `demo1234`) on every boot,
  so the demo always works. That password is public — don't put real data in that account.
- For real use, add a persistent disk (paid) or move to a real database.

## Option A — Render (recommended; `render.yaml` is included)
1. Push the project to GitHub (`.env`, the database and uploaded files are already gitignored).
2. On render.com: **New → Blueprint**, pick the repo. It reads `render.yaml`.
3. When asked, leave `NOTARIZATION_CONTRACT_ADDRESS` blank for now. `SECRET_KEY` is generated for you.
4. Wait for the first deploy, then open `https://<your-app>.onrender.com`.
   The first visit after idle takes ~30–60 s (free tier waking up).
5. To turn on notarization: Render → Environment → set `NOTARIZATION_CONTRACT_ADDRESS` to your
   Amoy contract (see `CONTRACT_DEPLOY.md`) → it redeploys. MetaMask needs the site on https, which Render provides.

## Option B — Railway
New project → Deploy from GitHub. It uses the `Procfile`. Add variables: `SECRET_KEY` (generate with
`python -c "import secrets; print(secrets.token_hex(32))"`), `FLASK_ENV_PRODUCTION=true`, `SEED_DEMO=true`.
Add a build step `python vendor_ethers.py` if you want notarization.

## Option C — PythonAnywhere
Clone the repo in a Bash console, create a virtualenv, `pip install -r requirements.txt`,
`python vendor_ethers.py` (paid accounts only for outside internet; free accounts must upload the file),
`python seed_demo.py`, then create a Flask web app pointing at `app.py` and set the same environment variables
in the WSGI file. Its disk persists, which suits this app better than Render's free tier.

## Environment variables
| Name | Value |
|---|---|
| `SECRET_KEY` | long random string (required in production) |
| `FLASK_ENV_PRODUCTION` | `true` (secure cookies, trusts the host's proxy, refuses to start without a real key) |
| `SEED_DEMO` | `true` for a demo site |
| `NOTARIZATION_CONTRACT_ADDRESS` | your deployed contract, optional |
| `POLYGON_AMOY_RPC_URL` | optional; defaults to the public Amoy RPC |

## Final demo walkthrough (run on the live URL)
Tick each box. Demo login: `demo@vault.local` / `demo1234`.
- [ ] `/healthz` shows `ok`; home page loads with correct fonts
- [ ] Register a new account (password 8+ chars) → log in → dashboard greets you
- [ ] Log in as the demo user → dashboard shows assets, nominees, completeness (~92%), tasks
- [ ] Assets, Nominees: add, edit, delete one each; assign a nominee to an asset
- [ ] Will: add an instruction tied to an asset; **Checker** flags "Mutual Fund" with WARNING
- [ ] Documents: upload a PDF; try a `.exe` and an oversized file (friendly errors); download one
- [ ] Digital Legacy, Trusted Contacts, Tasks (quick status change): add/edit/delete one each
- [ ] Life Verification: check in; simulate a missed check-in; check in again
- [ ] Wrong password 5 times → "Too many tries" message
- [ ] Log out (button in the menu), and confirm a protected page sends you back to log in
- [ ] Phone: menu opens/closes, tables become cards, nothing scrolls sideways
- [ ] (Notarization) Upload with the box ticked → **Notarize** in MetaMask on Amoy → badge **Notarized** → **Verify** → **Verified**
- [ ] (Notarization) Confirm "Not notarized" shows on a plain document

## Before sharing the link
- Run `python security_audit.py` and `python smoke_test.py` locally first — both should pass.
- Never put a seed phrase or private key anywhere in the project or the host's settings.
