import numpy as np
import pandas as pd
from faker import Faker
import json
from datetime import datetime, timedelta
from pathlib import Path

RNG_SEED = 42
np.random.seed(RNG_SEED)
fake = Faker()
Faker.seed(RNG_SEED)

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

# ----------------------------------------------------------------------------
# Enterprise configuration
# ----------------------------------------------------------------------------
N_EMPLOYEES = 500
N_DAYS = 90
START_DATE = datetime(2025, 4, 1)

DEPARTMENTS = {
    "Engineering":   {"resources": ["git_repo", "ci_pipeline", "prod_db", "staging_env", "internal_wiki"], "hours": (9, 19),  "geo": "IN"},
    "Finance":       {"resources": ["finance_db", "payroll_api", "expense_portal", "erp_system"],          "hours": (9, 18),  "geo": "IN"},
    "Sales":         {"resources": ["crm", "quote_tool", "email", "calendar"],                             "hours": (8, 20),  "geo": "IN"},
    "HR":            {"resources": ["hr_portal", "payroll_api", "recruiting_db", "email"],                 "hours": (9, 17),  "geo": "IN"},
    "IT_Admin":      {"resources": ["admin_console", "vpn_gateway", "server_ssh", "identity_provider"],    "hours": (0, 24),  "geo": "IN"},
    "Marketing":     {"resources": ["cms", "analytics", "social_tool", "email"],                           "hours": (9, 18),  "geo": "IN"},
    "Legal":         {"resources": ["contract_db", "compliance_portal", "email"],                          "hours": (9, 18),  "geo": "IN"},
}

# Sensitivity weighting used later by the risk engine (0-1)
RESOURCE_SENSITIVITY = {
    "payroll_api": 1.0, "finance_db": 1.0, "prod_db": 0.9, "erp_system": 0.9,
    "server_ssh": 0.9, "admin_console": 1.0, "identity_provider": 1.0,
    "vpn_gateway": 0.8, "contract_db": 0.8, "hr_portal": 0.7, "recruiting_db": 0.6,
    "git_repo": 0.6, "ci_pipeline": 0.6, "crm": 0.5, "expense_portal": 0.5,
    "compliance_portal": 0.6, "staging_env": 0.4, "internal_wiki": 0.2,
    "email": 0.3, "calendar": 0.1, "cms": 0.4, "analytics": 0.4,
    "social_tool": 0.3, "quote_tool": 0.4,
}

DEVICE_OS = ["Windows 11", "macOS 14", "Ubuntu 22.04", "iOS 17", "Android 14"]
AUTH_METHODS = ["password", "token", "certificate", "biometric"]
HOME_GEO = "IN"  # normal country for the enterprise

# ----------------------------------------------------------------------------
# 1. Build employees (Behaviour DNA source of truth)
# ----------------------------------------------------------------------------
def build_entities():
    dept_names = list(DEPARTMENTS.keys())
    # weight so Engineering/Sales are larger
    dept_weights = np.array([0.28, 0.10, 0.22, 0.08, 0.06, 0.14, 0.12])
    dept_weights = dept_weights / dept_weights.sum()

    entities = {}
    managers = {d: None for d in dept_names}
    # assign a manager per department first
    for i, d in enumerate(dept_names):
        mgr_id = f"U{i:04d}"
        managers[d] = mgr_id

    for i in range(N_EMPLOYEES):
        uid = f"U{i:04d}"
        dept = np.random.choice(dept_names, p=dept_weights) if uid not in managers.values() else \
               [d for d, m in managers.items() if m == uid][0]
        cfg = DEPARTMENTS[dept]
        h_start, h_end = cfg["hours"]
        # personal working window jitter within department norms
        pstart = max(0, h_start + np.random.randint(-1, 2))
        pend = min(24, h_end + np.random.randint(-1, 2))
        if pend <= pstart:
            pend = min(24, pstart + 8)
        n_devices = np.random.choice([1, 2, 3], p=[0.5, 0.4, 0.1])
        devices = [f"{uid}-D{j}" for j in range(n_devices)]
        device_os = {dev: np.random.choice(DEVICE_OS) for dev in devices}
        # each employee habitually touches a subset of their dept resources
        n_res = max(2, int(len(cfg["resources"]) * np.random.uniform(0.5, 1.0)))
        fav_res = list(np.random.choice(cfg["resources"], size=n_res, replace=False))

        entities[uid] = {
            "entity_id": uid,
            "entity_type": "service_account" if dept == "IT_Admin" and np.random.rand() < 0.2 else "user",
            "name": fake.name(),
            "department": dept,
            "manager": managers[dept] if managers[dept] != uid else "CISO",
            "work_start": int(pstart),
            "work_end": int(pend),
            "devices": devices,
            "device_os": device_os,
            "home_geo": HOME_GEO,
            "favourite_resources": fav_res,
            "avg_sessions_per_day": float(np.clip(np.random.normal(4, 1.5), 1, 12)),
            "avg_session_minutes": float(np.clip(np.random.normal(35, 15), 5, 180)),
        }
    return entities

# ----------------------------------------------------------------------------
# 2. Generate benign baseline activity
# ----------------------------------------------------------------------------
def geo_ip(geo):
    # crude but deterministic-ish IP block per geo
    blocks = {"IN": "49.36", "DE": "91.66", "US": "173.12", "RU": "95.24", "BR": "179.48", "NG": "105.112"}
    b = blocks.get(geo, "49.36")
    return f"{b}.{np.random.randint(0,255)}.{np.random.randint(1,254)}"

def gen_benign(entities):
    rows = []
    for uid, e in entities.items():
        for day in range(N_DAYS):
            date = START_DATE + timedelta(days=day)
            is_weekend = date.weekday() >= 5
            # fewer sessions on weekends
            lam = e["avg_sessions_per_day"] * (0.2 if is_weekend else 1.0)
            n_sessions = np.random.poisson(max(0.05, lam))
            for _ in range(n_sessions):
                hour = int(np.clip(np.random.normal((e["work_start"]+e["work_end"])/2,
                                                    (e["work_end"]-e["work_start"])/4),
                                   0, 23))
                minute = np.random.randint(0, 60)
                ts = date.replace(hour=hour, minute=minute, second=np.random.randint(0,60))
                device = np.random.choice(e["devices"])
                resource = np.random.choice(e["favourite_resources"])
                # occasional legitimate reach outside favourites (noise)
                if np.random.rand() < 0.05:
                    resource = np.random.choice(DEPARTMENTS[e["department"]]["resources"])
                dur = float(np.clip(np.random.normal(e["avg_session_minutes"], e["avg_session_minutes"]*0.4), 1, 300))
                rows.append({
                    "entity_id": uid,
                    "entity_type": e["entity_type"],
                    "timestamp": ts,
                    "source_ip": geo_ip(e["home_geo"]),
                    "geo_location": e["home_geo"],
                    "resource_accessed": resource,
                    "auth_method": np.random.choice(AUTH_METHODS, p=[0.5,0.3,0.1,0.1]),
                    "auth_success": True,
                    "session_duration": dur,
                    "device_id": device,
                    "device_os": e["device_os"][device],
                    "label": "normal",
                    "attack_id": "",
                })
    return rows

# ----------------------------------------------------------------------------
# 3. Inject attack taxonomy (labelled)
# ----------------------------------------------------------------------------
def inject_attacks(entities, benign_rows):
    uids = list(entities.keys())
    attack_rows = []
    attack_counter = 0

    def new_attack_id():
        nonlocal attack_counter
        attack_counter += 1
        return f"ATK{attack_counter:03d}"

    # target ~2% of total EVENTS as attack events. Because several attack
    # types emit many events per incident (brute force, lateral movement),
    # we scale the number of *incidents* down accordingly.
    target = int(len(benign_rows) * 0.02)

    # ---- Brute force: many rapid failed auths from one source ----
    # emits ~8-25 events each, so divide incident count by ~50
    for _ in range(max(3, target // 50)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        day = np.random.randint(0, N_DAYS)
        base = (START_DATE + timedelta(days=day)).replace(hour=np.random.randint(0,24), minute=0)
        src = geo_ip(np.random.choice(["RU","NG","BR"]))
        for k in range(np.random.randint(8, 25)):
            ts = base + timedelta(seconds=k*np.random.randint(2,8))
            attack_rows.append({**_blank(uid,e), "timestamp": ts, "source_ip": src,
                "geo_location": "RU", "resource_accessed": "identity_provider",
                "auth_method": "password", "auth_success": k >= np.random.randint(8,25)-1,
                "session_duration": 0.2, "device_id": "unknown", "device_os": "Ubuntu 22.04",
                "label": "brute_force", "attack_id": aid})

    # ---- Credential stuffing: many entity_ids, few IPs, high failure ----
    for _ in range(target // 6 // 12):
        aid = new_attack_id()
        src = geo_ip("RU")
        victims = np.random.choice(uids, size=np.random.randint(10,20), replace=False)
        day = np.random.randint(0, N_DAYS)
        base = (START_DATE + timedelta(days=day)).replace(hour=np.random.randint(0,24))
        for v in victims:
            e = entities[v]
            ts = base + timedelta(seconds=int(np.random.randint(0,600)))
            attack_rows.append({**_blank(v,e), "timestamp": ts, "source_ip": src,
                "geo_location": "RU", "resource_accessed": "identity_provider",
                "auth_method": "password", "auth_success": np.random.rand()<0.1,
                "session_duration": 0.2, "device_id": "unknown", "device_os": "Ubuntu 22.04",
                "label": "credential_stuffing", "attack_id": aid})

    # ---- Impossible travel: same id, distant geos in implausible gap ----
    # emits 2 events each
    for _ in range(max(3, target // 12)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        day = np.random.randint(0, N_DAYS)
        base = (START_DATE + timedelta(days=day)).replace(hour=np.random.randint(8,18))
        # legit-looking login at home
        attack_rows.append({**_blank(uid,e), "timestamp": base, "source_ip": geo_ip("IN"),
            "geo_location":"IN","resource_accessed": np.random.choice(e["favourite_resources"]),
            "auth_method":"password","auth_success":True,"session_duration":20.0,
            "device_id": np.random.choice(e["devices"]), "device_os": e["device_os"][e["devices"][0]],
            "label":"impossible_travel","attack_id":aid})
        # foreign login minutes later
        foreign = np.random.choice(["DE","US","RU","BR"])
        attack_rows.append({**_blank(uid,e), "timestamp": base+timedelta(minutes=np.random.randint(3,25)),
            "source_ip": geo_ip(foreign), "geo_location": foreign,
            "resource_accessed": np.random.choice(["finance_db","payroll_api","prod_db"]),
            "auth_method":"password","auth_success":True,"session_duration":15.0,
            "device_id":"unknown","device_os":"Ubuntu 22.04",
            "label":"impossible_travel","attack_id":aid})

    # ---- Device spoofing: known id, mismatched fingerprint (1 event each) ----
    for _ in range(max(3, target // 8)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        day = np.random.randint(0, N_DAYS)
        ts = (START_DATE+timedelta(days=day)).replace(hour=np.random.randint(0,24))
        wrong_os = np.random.choice([o for o in DEVICE_OS if o not in e["device_os"].values()] or DEVICE_OS)
        attack_rows.append({**_blank(uid,e), "timestamp": ts, "source_ip": geo_ip("IN"),
            "geo_location":"IN","resource_accessed": np.random.choice(DEPARTMENTS[e["department"]]["resources"]),
            "auth_method":"token","auth_success":True,"session_duration":25.0,
            "device_id": e["devices"][0], "device_os": wrong_os,  # same device id, wrong OS
            "label":"device_spoofing","attack_id":aid})

    # ---- Lateral movement: compromised id touches unusual breadth ----
    # emits ~5-10 events each, so divide by ~15
    for _ in range(max(3, target // 15)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        day = np.random.randint(0, N_DAYS)
        base = (START_DATE+timedelta(days=day)).replace(hour=np.random.randint(1,5))  # off hours
        unusual = [r for dept in DEPARTMENTS.values() for r in dept["resources"]
                   if r not in e["favourite_resources"]]
        touched = np.random.choice(unusual, size=np.random.randint(5,10), replace=False)
        for k, r in enumerate(touched):
            ts = base + timedelta(minutes=k*np.random.randint(2,6))
            attack_rows.append({**_blank(uid,e), "timestamp": ts, "source_ip": geo_ip("IN"),
                "geo_location":"IN","resource_accessed": r, "auth_method":"token",
                "auth_success":True,"session_duration":8.0,
                "device_id": e["devices"][0], "device_os": e["device_os"][e["devices"][0]],
                "label":"lateral_movement","attack_id":aid})

    # ---- Low-and-slow exfiltration: small off-hours access over many days ----
    # emits 10-20 events each, so keep incident count low
    for _ in range(max(2, target // 60)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        start_day = np.random.randint(0, N_DAYS-20)
        for d in range(np.random.randint(10, 20)):
            ts = (START_DATE+timedelta(days=start_day+d)).replace(hour=np.random.choice([1,2,3,23]))
            attack_rows.append({**_blank(uid,e), "timestamp": ts, "source_ip": geo_ip("IN"),
                "geo_location":"IN","resource_accessed": np.random.choice(["finance_db","prod_db","contract_db"]),
                "auth_method":"token","auth_success":True,"session_duration":float(np.random.uniform(2,6)),
                "device_id": e["devices"][0], "device_os": e["device_os"][e["devices"][0]],
                "label":"low_and_slow","attack_id":aid})

    # ---- Insider drift: legit slow expansion — EDGE CASE, labelled benign-ambiguous ----
    for _ in range(max(2, target // 80)):
        uid = np.random.choice(uids); e = entities[uid]
        aid = new_attack_id()
        start_day = np.random.randint(0, N_DAYS-30)
        extra = [r for r in DEPARTMENTS[e["department"]]["resources"] if r not in e["favourite_resources"]]
        if not extra:
            continue
        for d in range(0, 30, 3):
            ts = (START_DATE+timedelta(days=start_day+d)).replace(hour=int((e["work_start"]+e["work_end"])//2))
            r = np.random.choice(extra)
            attack_rows.append({**_blank(uid,e), "timestamp": ts, "source_ip": geo_ip("IN"),
                "geo_location":"IN","resource_accessed": r, "auth_method":"password",
                "auth_success":True,"session_duration": e["avg_session_minutes"],
                "device_id": np.random.choice(e["devices"]), "device_os": e["device_os"][e["devices"][0]],
                "label":"insider_drift","attack_id":aid})  # ambiguous: used for FP tuning

    return attack_rows

def _blank(uid, e):
    return {"entity_id": uid, "entity_type": e["entity_type"]}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    print("Building enterprise…")
    entities = build_entities()
    print(f"  {len(entities)} employees across {len(DEPARTMENTS)} departments")

    print("Generating benign baseline (90 days)…")
    benign = gen_benign(entities)
    print(f"  {len(benign):,} benign events")

    print("Injecting attack taxonomy…")
    attacks = inject_attacks(entities, benign)
    print(f"  {len(attacks):,} attack events")

    df = pd.DataFrame(benign + attacks)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = [f"E{i:07d}" for i in range(len(df))]

    # attach resource sensitivity for downstream risk engine
    df["resource_sensitivity"] = df["resource_accessed"].map(RESOURCE_SENSITIVITY).fillna(0.3)

    rate = (df["label"] != "normal").mean() * 100
    print(f"\nTotal events: {len(df):,}")
    print(f"Attack/anomaly rate: {rate:.2f}% (target 0.5-3%)")
    print("\nLabel distribution:")
    print(df["label"].value_counts().to_string())

    df.to_parquet(DATA_DIR / "events.parquet", index=False)
    with open(DATA_DIR / "entities.json", "w") as f:
        json.dump(entities, f, indent=2, default=str)
    print(f"\nSaved -> {DATA_DIR/'events.parquet'} and entities.json")

if __name__ == "__main__":
    main()
