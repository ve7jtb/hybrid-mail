#!/usr/bin/env python3
"""Fail packaging if native passkeys lack a valid signed association/profile."""
import datetime
import pathlib
import plistlib
import subprocess
import sys

app = pathlib.Path(sys.argv[1])
team = sys.argv[2] if len(sys.argv) > 2 else None
subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
entitlements = plistlib.loads(subprocess.check_output(
    ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(app)], stderr=subprocess.DEVNULL))
profile = plistlib.loads(subprocess.check_output(
    ["/usr/bin/security", "cms", "-D", "-i", str(app / "Contents/embedded.provisionprofile")]))
allowed = profile["Entitlements"]
team = team or entitlements["com.apple.developer.team-identifier"]
app_id = team + ".io.github.ve7jtb.pqmail.passkey"
domain = "webcredentials:ve7jtb.github.io"
assert entitlements.get("com.apple.application-identifier") == app_id, "Wrong signed application identity"
assert allowed.get("com.apple.application-identifier") == app_id, "Wrong provisioned application identity"
assert entitlements.get("com.apple.developer.team-identifier") == team, "Wrong signing team"
assert entitlements.get("com.apple.developer.associated-domains") == [domain], "Wrong signed RP association"
assert any(x in (domain, "*") for x in allowed.get("com.apple.developer.associated-domains", [])), "Associated Domains not provisioned"
assert profile["ExpirationDate"].replace(tzinfo=datetime.timezone.utc) > datetime.datetime.now(datetime.timezone.utc), "Expired passkey provisioning profile"
print("PASS native passkey helper signature, team, app ID, domain entitlement and profile expiration")
