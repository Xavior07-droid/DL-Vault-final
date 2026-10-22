#!/bin/sh
# Start command for hosting platforms (Render, Railway, ...).
# SEED_DEMO=true creates the demo account (demo@vault.local) on boot if it is
# missing — handy on free hosts whose disk is wiped on every restart.
if [ "$SEED_DEMO" = "true" ]; then
    python seed_demo.py
fi
# ONE worker on purpose: SQLite is a single file and the login throttle lives in memory.
exec gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:${PORT:-8000}
