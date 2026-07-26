import numpy as np, pandas as pd, json
from pathlib import Path
from sklearn.metrics.pairwise import cosine_similarity

R = Path(__file__).parent / "results"
from profiling_and_features import FEATURE_NAMES

scored = pd.read_parquet(R / "scored_test.parquet")
Xte = np.load(R / "X_test.npy")
mte = pd.read_parquet(R / "meta_test.parquet")
entities = json.load(open(Path(__file__).parent / "data" / "entities.json"))
metrics = json.load(open(R / "metrics.json"))

# align X with scored rows (meta_test order == scored order == X order)
assert len(Xte) == len(scored) == len(mte)

GEO_NAME = {"IN":"India","DE":"Germany","US":"United States","RU":"Russia","BR":"Brazil","NG":"Nigeria"}
TYPE_LABEL = {
    "brute_force":"Brute Force","credential_stuffing":"Credential Stuffing",
    "impossible_travel":"Impossible Travel","device_spoofing":"Device Spoofing",
    "lateral_movement":"Lateral Movement","low_and_slow":"Low-and-Slow Exfiltration",
    "insider_drift":"Insider Drift (benign)",
}
SEVERITY = {  # for threat score weighting
    "brute_force":0.7,"credential_stuffing":0.75,"impossible_travel":0.9,
    "device_spoofing":0.8,"lateral_movement":0.95,"low_and_slow":0.85,"insider_drift":0.3,
}

# ---- select incidents: top ~3% by score, that carry an attack_id ----
budget = int(0.03 * len(scored))
top = scored.assign(rowidx=np.arange(len(scored))).sort_values("anomaly_score", ascending=False).head(budget)
top = top[top["attack_id"] != ""]

def narrate(inc, ent):

    t0 = inc["events"][0]
    geo = GEO_NAME.get(t0["geo"], t0["geo"])
    typ = TYPE_LABEL.get(inc["true_type"], inc["true_type"])
    when = pd.to_datetime(t0["timestamp"]).strftime("%b %d, %H:%M")
    res = ", ".join(sorted({e["resource"] for e in inc["events"]})[:3])
    dev_note = ""
    if any(e["os_mismatch"] for e in inc["events"]):
        dev_note = " using a device whose fingerprint did not match its history"
    lines = [
        f"At {when}, {ent['name']} ({ent['department']}) showed activity from {geo}{dev_note}.",
        f"The session touched {res}.",
        f"Behaviour diverged from the entity's established Behaviour DNA across "
        f"{inc['n_factors']} signals.",
        f"Classified as {typ} with a threat score of {inc['threat_score']}.",
    ]
    return " ".join(lines)

# precompute rank-normalized anomaly score across the flagged/top set for spread
_top_scores = top["anomaly_score"].values
_rank = (np.argsort(np.argsort(_top_scores)) / (len(_top_scores)-1+1e-9))
top = top.assign(score_rank=_rank)

incidents = []
for aid, g in top.groupby("attack_id"):
    idxs = g["rowidx"].values
    true_type = g["label"].iloc[0]
    eid = g["entity_id"].iloc[0]
    ent = entities.get(eid, {"name": eid, "department": "Unknown"})
    # feature attribution: mean z over the incident's events
    mu, sd = Xte.mean(0), Xte.std(0) + 1e-9
    z = ((Xte[idxs] - mu) / sd).mean(0)
    factors = sorted([(FEATURE_NAMES[j], round(float(z[j]),2)) for j in range(len(FEATURE_NAMES))],
                     key=lambda kv: -abs(kv[1]))
    top_factors = [{"feature": f.replace("_"," "), "z": v} for f, v in factors[:4] if abs(v) > 0.3]
    # threat score 30-99: rank within flagged set, nudged by severity & sensitivity
    rank_mean = float(g["score_rank"].mean())
    sens = float(g["resource_sensitivity"].max())
    sev = SEVERITY.get(true_type, 0.6)
    threat = int(round(30 + 69 * (0.6*rank_mean + 0.25*sev + 0.15*sens)))
    threat = max(30, min(99, threat))
    events = []
    for r in g.sort_values("timestamp").itertuples(index=False):
        ii = int(getattr(r, "rowidx"))
        events.append({
            "timestamp": str(r.timestamp), "geo": r.geo_location,
            "resource": r.resource_accessed, "device": r.device_id,
            "os_mismatch": bool(Xte[ii][FEATURE_NAMES.index("os_mismatch")] > 0.5),
            "auth_success": bool(r.auth_success),
        })
    inc = {
        "incident_id": f"INC-{len(incidents)+1:03d}",
        "attack_id": aid, "entity_id": eid, "entity_name": ent["name"],
        "department": ent["department"], "true_type": true_type,
        "type_label": TYPE_LABEL.get(true_type, true_type),
        "n_events": int(len(g)), "n_factors": len(top_factors),
        "threat_score": threat, "top_factors": top_factors,
        "feature_vector": z.round(3).tolist(),
        "events": events,
        "geo": g["geo_location"].mode().iloc[0],
        "timestamp": str(g["timestamp"].min()),
    }
    inc["narrative"] = narrate(inc, ent)
    inc["recommended_actions"] = {
        "brute_force": ["Lock account", "Block source IP", "Force password reset"],
        "credential_stuffing": ["Enforce MFA", "Block source IP", "Notify affected users"],
        "impossible_travel": ["Lock account", "Revoke active sessions", "Verify with user"],
        "device_spoofing": ["Quarantine device", "Re-enroll device", "Review access logs"],
        "lateral_movement": ["Isolate host", "Revoke elevated access", "Escalate to SOC"],
        "low_and_slow": ["Review data access", "Enable DLP monitoring", "Escalate to SOC"],
        "insider_drift": ["Confirm with manager", "No block — monitor"],
    }.get(true_type, ["Escalate to SOC"])
    incidents.append(inc)

# sort by threat score desc
incidents.sort(key=lambda x: -x["threat_score"])
# re-id after sort so INC-001 is highest threat
for i, inc in enumerate(incidents):
    inc["incident_id"] = f"INC-{i+1:03d}"

# ---- Threat Memory: cosine similarity between incident feature vectors ----
vecs = np.array([inc["feature_vector"] for inc in incidents])
sim = cosine_similarity(vecs)
correlations = {}
for i, inc in enumerate(incidents):
    sims = [(incidents[j]["incident_id"], round(float(sim[i,j]),3), incidents[j]["type_label"])
            for j in range(len(incidents)) if j != i]
    sims.sort(key=lambda x: -x[1])
    correlations[inc["incident_id"]] = [
        {"incident_id": s[0], "similarity": s[1], "type": s[2]} for s in sims[:3] if s[1] > 0.6
    ]

# ---- Dashboard aggregates ----
by_type = scored[scored.label!="normal"]["label"].map(lambda x: TYPE_LABEL.get(x,x)).value_counts().to_dict()
by_dept = {}
for inc in incidents:
    by_dept[inc["department"]] = by_dept.get(inc["department"],0)+1
# org trust score: 100 minus a penalty scaled by critical-incident density
_critical = sum(1 for i in incidents if i["threat_score"]>=80)
trust = max(55, int(100 - _critical*0.8 - (len(incidents)-_critical)*0.15))

# ---- Attack injection scenarios: precomputed examples per type ----
scenarios = {}
for inc in incidents:
    scenarios.setdefault(inc["true_type"], inc["incident_id"])

app_data = {
    "meta": {
        "n_employees": len(entities),
        "n_test_events": int(len(scored)),
        "n_incidents": len(incidents),
        "roc_auc": metrics["detection"]["roc_auc"],
        "pr_auc": metrics["detection"]["pr_auc"],
    },
    "incidents": incidents,
    "correlations": correlations,
    "dashboard": {
        "by_type": by_type, "by_department": by_dept,
        "org_trust": trust,
        "critical_incidents": sum(1 for i in incidents if i["threat_score"]>=80),
        "total_incidents": len(incidents),
    },
    "injection_scenarios": scenarios,
    "attack_types": list(TYPE_LABEL.items()),
}
json.dump(app_data, open(R / "app_data.json","w"), indent=2, default=str)
print(f"Built {len(incidents)} incidents, "
      f"{sum(len(v) for v in correlations.values())} correlations.")
print(f"Org trust: {trust}  Critical: {app_data['dashboard']['critical_incidents']}")
print("Sample incident:", incidents[0]["incident_id"], incidents[0]["type_label"],
      "threat", incidents[0]["threat_score"])
print("Narrative:", incidents[0]["narrative"][:120], "…")
