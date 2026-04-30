"""Probe POST /api/cases with every likely frontend payload shape."""
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:5000"

def login():
    req = urllib.request.Request(
        f"{BASE}/api/auth/login",
        data=json.dumps({"email": "admin@chaincustody.local", "password": "Admin@12345"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())["data"]["access_token"]

def post_case(token, payload):
    req = urllib.request.Request(
        f"{BASE}/api/cases",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

token = login()
print("Token obtained\n")

scenarios = [
    # canonical
    ("canonical snake_case",        {"title": "Test", "fraud_type": "SIM_SWAP"}),
    # title aliases
    ("case_title alias",            {"case_title": "Test", "fraud_type": "SIM_SWAP"}),
    ("caseTitle alias",             {"caseTitle": "Test", "fraud_type": "SIM_SWAP"}),
    ("caseName alias",              {"caseName": "Test", "fraud_type": "SIM_SWAP"}),
    ("name alias",                  {"name": "Test", "fraud_type": "SIM_SWAP"}),
    # fraud_type aliases
    ("fraudType camelCase",         {"title": "Test", "fraudType": "SIM_SWAP"}),
    ("fraud_type lowercase",        {"title": "Test", "fraud_type": "sim_swap"}),
    ("fraud_type spaces",           {"title": "Test", "fraud_type": "SIM SWAP"}),
    ("fraud_type BEC alias",        {"title": "Test", "fraud_type": "BEC"}),
    ("fraud_type display label",    {"title": "Test", "fraud_type": "Business Email Compromise"}),
    ("fraud_type INSIDER FRAUD",    {"title": "Test", "fraud_type": "INSIDER FRAUD"}),
    ("fraud_type ACCOUNT TAKEOVER", {"title": "Test", "fraud_type": "ACCOUNT TAKEOVER"}),
    # error cases
    ("missing title",               {"fraud_type": "SIM_SWAP"}),
    ("empty body",                  {}),
    ("invalid fraud_type",          {"title": "Test", "fraud_type": "TOTALLY_WRONG"}),
]

print(f"{'STATUS':<6}  {'SCENARIO':<38}  RESPONSE")
print("-" * 90)
for label, payload in scenarios:
    code, body = post_case(token, payload)
    msg = body.get("message", str(body))[:70]
    mark = "OK " if code < 400 else "ERR"
    print(f"[{mark}] {code}  {label:<38}  {msg}")
