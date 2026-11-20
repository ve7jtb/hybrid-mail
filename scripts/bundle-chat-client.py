#!/usr/bin/env python3
"""Optional installed-app configuration. Never bundle user access/refresh tokens."""
import json, os
from pathlib import Path
out = Path('build/classes/google-chat-client.json')
source = os.environ.get('PQ_MAIL_CHAT_CLIENT_JSON')
if source:
    config = json.loads(Path(source).read_text())['installed']
    assert config['client_id'].endswith('.apps.googleusercontent.com')
    assert len(config.get('client_secret', '')) <= 1024
    # Explicit allowlist prevents accidental packaging of any user credentials.
    out.write_text(json.dumps({'installed': {k: config.get(k, '') for k in ('client_id', 'client_secret', 'project_id')}}))
elif out.exists():
    out.unlink()  # A previous configured build must not contaminate another build.
