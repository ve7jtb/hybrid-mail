#!/usr/bin/env python3
"""Inject optional public installed-app configuration, without logging its value."""
import json
import os
from pathlib import Path
root = Path(__file__).resolve().parent.parent
out = root / 'build/classes/google-client.json'
secret = os.environ.get('PQ_MAIL_GOOGLE_CLIENT_SECRET', '')
local = root / 'google-client.json'
if secret:
    config = {'id': '840275251476-moq0vdvvk3coecfn2sl3a2elfl00lrfu.apps.googleusercontent.com', 'secret': secret}
elif local.exists():
    config = json.loads(local.read_text())
else:
    out.unlink(missing_ok=True)
    print('No bundled Google client; custom client import remains available.')
    raise SystemExit(0)
if not isinstance(config.get('id'), str) or not config['id'].endswith('.apps.googleusercontent.com') or not isinstance(config.get('secret'), str):
    raise SystemExit('Invalid Google client build configuration')
out.write_text(json.dumps(config))
out.chmod(0o600)
print('Bundled installed-app Google client configuration.')
