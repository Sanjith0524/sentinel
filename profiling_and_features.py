import numpy as np
import pandas as pd
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Train on first 70% of the timeline, test on last 30% (temporal split — this
# is what makes concept-drift and cold-start evaluation meaningful).
TRAIN_FRACTION = 0.70

GEO_COORDS = {  # approx lat/lon for geo-velocity calc
    "IN": (20.6, 78.9), "DE": (51.2, 10.4), "US": (37.1, -95.7),
    "RU": (61.5, 105.3), "BR": (-14.2, -51.9), "NG": (9.1, 8.7),
}

def haversine(a, b):
    lat1, lon1 = np.radians(GEO_COORDS.get(a, GEO_COORDS["IN"]))
    lat2, lon2 = np.radians(GEO_COORDS.get(b, GEO_COORDS["IN"]))
    dlat, dlon = lat2-lat1, lon2-lon1
    h = np.sin(dlat/2)**2 + np.cos(lat1)*np.cos(lat2)*np.sin(dlon/2)**2
    return 2*6371*np.arcsin(np.sqrt(h))  # km

def load():
    df = pd.read_parquet(DATA_DIR / "events.parquet")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    with open(DATA_DIR / "entities.json") as f:
        entities = json.load(f)
    return df, entities

def temporal_split(df, coldstart_holdout=0.06, seed=42):

    rng = np.random.default_rng(seed)
    all_entities = df["entity_id"].unique()
    n_hold = int(len(all_entities) * coldstart_holdout)
    coldstart_entities = set(rng.choice(all_entities, size=n_hold, replace=False))

    cutoff = df["timestamp"].quantile(TRAIN_FRACTION)
    train = df[(df["timestamp"] <= cutoff) &
               (~df["entity_id"].isin(coldstart_entities))].copy()
    test = df[df["timestamp"] > cutoff].copy()
    return train, test, cutoff, coldstart_entities

# ----------------------------------------------------------------------------
# Behaviour DNA — statistical profile built from TRAIN window, benign only
# ----------------------------------------------------------------------------
def build_profiles(train):
    # profiles are learned from what looked normal; we use all train rows but
    # the benign majority dominates the statistics (robust to small attack %)
    profiles = {}
    dept_profiles = {}  # for cold-start fallback

    for eid, g in train.groupby("entity_id"):
        hours = g["timestamp"].dt.hour
        profiles[eid] = {
            "n_events": int(len(g)),
            "hour_mean": float(hours.mean()),
            "hour_std": float(hours.std() or 1.0),
            "geos": g["geo_location"].value_counts(normalize=True).to_dict(),
            "devices": set(g["device_id"].unique().tolist()),
            "device_os": set(g["device_os"].unique().tolist()),
            "resources": g["resource_accessed"].value_counts(normalize=True).to_dict(),
            "dur_mean": float(g["session_duration"].mean()),
            "dur_std": float(g["session_duration"].std() or 1.0),
            "fail_rate": float((~g["auth_success"]).mean()),
        }
    return profiles

def build_dept_profiles(train, entities):
    # map entity -> department, aggregate for cold-start
    ent_dept = {k: v["department"] for k, v in entities.items()}
    train = train.copy()
    train["department"] = train["entity_id"].map(ent_dept)
    dept_profiles = {}
    for dept, g in train.groupby("department"):
        hours = g["timestamp"].dt.hour
        dept_profiles[dept] = {
            "hour_mean": float(hours.mean()),
            "hour_std": float(hours.std() or 1.0),
            "geos": g["geo_location"].value_counts(normalize=True).to_dict(),
            "resources": g["resource_accessed"].value_counts(normalize=True).to_dict(),
            "dur_mean": float(g["session_duration"].mean()),
            "dur_std": float(g["session_duration"].std() or 1.0),
        }
    return dept_profiles, ent_dept

# ----------------------------------------------------------------------------
# Sequence-aware feature vector per event
# ----------------------------------------------------------------------------
def featurize(df, profiles, dept_profiles, ent_dept, is_train=True):

    feats = []
    # precompute per-entity previous event for geo-velocity & timing
    df = df.sort_values(["entity_id", "timestamp"]).reset_index(drop=True)
    prev_ts = {}
    prev_geo = {}
    # rolling failure counts per (entity, short window) approximated per row
    fail_window = {}

    coldstart_flags = []
    # Pre-compute per-entity rolling failure bursts (sequence signal for brute
    # force) and per-source-IP spread (credential stuffing signal).
    df_idx = df.reset_index(drop=True)
    # rolling count of failures in last 5 events per entity
    fail_burst = np.zeros(len(df_idx))
    recent_fail = {}
    for i, row in enumerate(df_idx.itertuples(index=False)):
        eid = row.entity_id
        buf = recent_fail.setdefault(eid, [])
        buf.append(0 if row.auth_success else 1)
        if len(buf) > 5:
            buf.pop(0)
        fail_burst[i] = sum(buf)
    # per source_ip: how many distinct entities used it (stuffing signal)
    ip_spread = df_idx.groupby("source_ip")["entity_id"].transform("nunique").values
    ip_spread_norm = np.tanh(ip_spread / 10.0)

    for i, row in enumerate(df_idx.itertuples(index=False)):
        eid = row.entity_id
        p = profiles.get(eid)
        cold = p is None
        if cold:
            # cold-start fallback: use department baseline
            dept = ent_dept.get(eid, None)
            dp = dept_profiles.get(dept) if dept else None
            p = {
                "hour_mean": dp["hour_mean"] if dp else 12.0,
                "hour_std": dp["hour_std"] if dp else 6.0,
                "geos": dp["geos"] if dp else {"IN": 1.0},
                "devices": set(), "device_os": set(),
                "resources": dp["resources"] if dp else {},
                "dur_mean": dp["dur_mean"] if dp else 30.0,
                "dur_std": dp["dur_std"] if dp else 20.0,
                "fail_rate": 0.05,
            }
        coldstart_flags.append(cold)

        hour = row.timestamp.hour
        # 1. hour deviation (z-score against profile)
        hour_z = abs(hour - p["hour_mean"]) / (p["hour_std"] + 1e-6)
        # 2. geo novelty: 1 - P(geo under profile)
        geo_p = p["geos"].get(row.geo_location, 0.0)
        geo_novelty = 1.0 - geo_p
        # 3. resource novelty
        res_p = p["resources"].get(row.resource_accessed, 0.0)
        res_novelty = 1.0 - res_p
        # 4. device unseen?
        device_unseen = 0.0 if row.device_id in p["devices"] else 1.0
        # 5. OS mismatch (spoofing signal)
        os_unseen = 0.0 if row.device_os in p["device_os"] else 1.0
        # 6. duration deviation
        dur_z = abs(row.session_duration - p["dur_mean"]) / (p["dur_std"] + 1e-6)
        # 7. auth failure
        auth_fail = 0.0 if row.auth_success else 1.0
        # 8. geo-velocity (km/h) vs previous event for this entity
        gv = 0.0
        if eid in prev_ts:
            dt_h = (row.timestamp - prev_ts[eid]).total_seconds() / 3600.0
            dist = haversine(prev_geo[eid], row.geo_location)
            gv = dist / dt_h if dt_h > 0.01 else (dist / 0.01 if dist > 0 else 0.0)
        gv_norm = np.tanh(gv / 1000.0)  # squash; >1000km/h is implausible
        prev_ts[eid] = row.timestamp
        prev_geo[eid] = row.geo_location
        # 9. inter-event gap (short = burst, e.g. brute force)
        # reuse dt from above if present
        gap_min = 999.0
        # 10. off-hours flag
        off_hours = 1.0 if (hour < 6 or hour > 22) else 0.0
        # 11. resource sensitivity
        sens = row.resource_sensitivity
        # 12. foreign geo flag
        foreign = 0.0 if row.geo_location == "IN" else 1.0
        # 13. failure-burst (rolling failed auths, brute-force signal)
        fburst = fail_burst[i] / 5.0
        # 14. source-IP spread (credential-stuffing signal)
        ipspread = ip_spread_norm[i]

        feats.append([
            hour_z, geo_novelty, res_novelty, device_unseen, os_unseen,
            dur_z, auth_fail, gv_norm, off_hours, sens, foreign,
            fburst, ipspread,
        ])

    X = np.array(feats, dtype=float)
    meta = df[["event_id", "entity_id", "timestamp", "geo_location",
               "resource_accessed", "device_id", "device_os",
               "auth_success", "resource_sensitivity", "label", "attack_id"]].reset_index(drop=True)
    meta["coldstart"] = coldstart_flags
    return X, meta

FEATURE_NAMES = [
    "hour_deviation", "geo_novelty", "resource_novelty", "device_unseen",
    "os_mismatch", "duration_deviation", "auth_failure", "geo_velocity",
    "off_hours", "resource_sensitivity", "foreign_geo",
    "failure_burst", "ip_spread",
]

if __name__ == "__main__":
    df, entities = load()
    train, test, cutoff, coldstart_entities = temporal_split(df)
    print(f"Train events: {len(train):,}  |  Test events: {len(test):,}  |  cutoff {cutoff}")
    print(f"Held-out cold-start entities: {len(coldstart_entities)}")
    profiles = build_profiles(train)
    dept_profiles, ent_dept = build_dept_profiles(train, entities)
    print(f"Built {len(profiles)} entity profiles, {len(dept_profiles)} dept profiles")

    Xtr, mtr = featurize(train, profiles, dept_profiles, ent_dept, is_train=True)
    Xte, mte = featurize(test, profiles, dept_profiles, ent_dept, is_train=False)
    print(f"Train X: {Xtr.shape}  Test X: {Xte.shape}")
    print(f"Cold-start entities in test: {mte['coldstart'].sum()} events")

    np.save(RESULTS_DIR / "X_train.npy", Xtr)
    np.save(RESULTS_DIR / "X_test.npy", Xte)
    mtr.to_parquet(RESULTS_DIR / "meta_train.parquet")
    mte.to_parquet(RESULTS_DIR / "meta_test.parquet")
    with open(RESULTS_DIR / "profiles.json", "w") as f:
        json.dump({k: {**v, "devices": list(v["devices"]), "device_os": list(v["device_os"])}
                   for k, v in profiles.items()}, f, default=str)
    print("Saved features + profiles.")
