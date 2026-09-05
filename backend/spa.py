"""
Helpers for serving the React SPA (frontend/dist) from the Flask app.

The SPA is served automatically as soon as `frontend/dist/index.html`
exists (i.e. after `cd frontend && npm run build`). Until then — or if
`FRONTEND_SPA` env var is explicitly '0' — the original Jinja templates
keep being served, so the switchover is incremental and reversible:

    FRONTEND_SPA=1 python run.py   # force SPA mode
    FRONTEND_SPA=0 python run.py   # force legacy Jinja mode

API routes (/api, /email/api, /forensic/api, Socket.IO) are untouched
in both modes — the SPA talks to exactly the same backend surface.
"""
import os
from pathlib import Path

from flask import send_from_directory

project_root = Path(__file__).resolve().parent.parent
SPA_DIST = project_root / 'frontend' / 'dist'


def spa_enabled() -> bool:
    force = os.getenv('FRONTEND_SPA', '').strip().lower()
    if force:
        return force in ('1', 'true', 'yes', 'on')
    return (SPA_DIST / 'index.html').exists()


def spa_index():
    return send_from_directory(SPA_DIST, 'index.html')


def spa_assets(filename: str):
    return send_from_directory(SPA_DIST / 'assets', filename)
