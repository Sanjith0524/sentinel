from flask import Flask, jsonify, request
from flask_cors import CORS
import json
from pathlib import Path

app = Flask(__name__)
CORS(app)

R = Path(__file__).resolve().parent.parent / "results"
APP_DATA = json.load(open(R / "app_data.json"))
METRICS = json.load(open(R / "metrics.json"))

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "meta": APP_DATA["meta"]})

@app.get("/api/dashboard")
def dashboard():
    return jsonify({
        "dashboard": APP_DATA["dashboard"],
        "meta": APP_DATA["meta"],
        "by_type": APP_DATA["dashboard"]["by_type"],
        "by_department": APP_DATA["dashboard"]["by_department"],
    })

@app.get("/api/incidents")
def incidents():
    limit = int(request.args.get("limit", 50))
    out = [{k: inc[k] for k in ("incident_id","entity_name","department","type_label",
            "threat_score","n_events","geo","timestamp","narrative")}
           for inc in APP_DATA["incidents"][:limit]]
    return jsonify({"incidents": out, "total": len(APP_DATA["incidents"])})

@app.get("/api/incident/<iid>")
def incident(iid):
    for inc in APP_DATA["incidents"]:
        if inc["incident_id"] == iid:
            corr = APP_DATA["correlations"].get(iid, [])
            return jsonify({"incident": inc, "correlations": corr})
    return jsonify({"error": "not found"}), 404

@app.get("/api/metrics")
def metrics():
    return jsonify(METRICS)

@app.get("/api/inject")
def inject():
    atype = request.args.get("type", "brute_force")
    iid = APP_DATA["injection_scenarios"].get(atype)
    if not iid:
        return jsonify({"error": "no scenario for type"}), 404
    for inc in APP_DATA["incidents"]:
        if inc["incident_id"] == iid:
            return jsonify({"incident": inc,
                            "correlations": APP_DATA["correlations"].get(iid, [])})
    return jsonify({"error": "not found"}), 404

@app.get("/api/attack_types")
def attack_types():
    return jsonify({"types": APP_DATA["attack_types"],
                    "scenarios": list(APP_DATA["injection_scenarios"].keys())})

import re

def _copilot_answer(q):
    ql = q.lower().strip()
    incs = APP_DATA["incidents"]
    dash = APP_DATA["dashboard"]

    m = re.search(r'(?:incident|inc)[\s\-#]*(\d+)', ql)
    if m and ("explain" in ql or "why" in ql or "tell" in ql or "what" in ql):
        num = int(m.group(1))
        iid = f"INC-{num:03d}"
        inc = next((i for i in incs if i["incident_id"] == iid), None)
        if inc:
            factors = ", ".join(f["feature"] for f in inc["top_factors"][:3])
            return {"answer": f"{iid} — {inc['type_label']} involving {inc['entity_name']} "
                    f"({inc['department']}), threat score {inc['threat_score']}. {inc['narrative']} "
                    f"Top contributing signals: {factors}.",
                    "cite": iid}
        return {"answer": f"I couldn't find incident {iid}. There are {len(incs)} incidents (INC-001 to INC-{len(incs):03d})."}

    if "why" in ql and ("flag" in ql or "user" in ql):
        for inc in incs:
            first = inc["entity_name"].split()[0].lower()
            if first in ql or inc["entity_name"].lower() in ql:
                factors = ", ".join(f["feature"] for f in inc["top_factors"][:3])
                return {"answer": f"{inc['entity_name']} was flagged in {inc['incident_id']} "
                        f"({inc['type_label']}, threat {inc['threat_score']}) because their behaviour "
                        f"deviated on: {factors}. {inc['narrative']}", "cite": inc["incident_id"]}
        return {"answer": "I couldn't match that name to a flagged user. Try 'show highest-risk users' to see who's flagged."}

    if ("highest" in ql or "top" in ql or "riskiest" in ql or "most risk" in ql) and \
       ("user" in ql or "risk" in ql or "incident" in ql):
        top = incs[:5]
        lines = [f"{i['incident_id']}: {i['entity_name']} ({i['department']}) — "
                 f"{i['type_label']}, threat {i['threat_score']}" for i in top]
        return {"answer": "Highest-risk incidents right now:\n" + "\n".join(lines)}

    if "summar" in ql or ("attack" in ql and ("today" in ql or "all" in ql or "overview" in ql)):
        bt = dash["by_type"]
        parts = ", ".join(f"{v} {k.lower()}" for k, v in sorted(bt.items(), key=lambda x:-x[1]))
        return {"answer": f"Across the monitored window there are {dash['total_incidents']} incidents, "
                f"{dash['critical_incidents']} critical (threat ≥ 80). By type: {parts}. "
                f"Organisation trust index is at {dash['org_trust']}%."}

    if "department" in ql and ("most" in ql or "attack" in ql or "risk" in ql):
        bd = dash["by_department"]
        if bd:
            top_dept = max(bd.items(), key=lambda x: x[1])
            ranked = ", ".join(f"{k} ({v})" for k, v in sorted(bd.items(), key=lambda x:-x[1]))
            return {"answer": f"{top_dept[0]} is the most-affected department with {top_dept[1]} incidents. "
                    f"Full ranking: {ranked}."}

    if "recommend" in ql or "mitigat" in ql or "what should" in ql or "action" in ql:
        crit = [i for i in incs if i["threat_score"] >= 80][:3]
        if crit:
            lines = [f"{i['incident_id']} ({i['type_label']}): {', '.join(i['recommended_actions'])}" for i in crit]
            return {"answer": "Priority mitigations for the top critical incidents:\n" + "\n".join(lines)}
        return {"answer": "No critical incidents currently need mitigation."}

    if "how many" in ql or "count" in ql:
        return {"answer": f"There are {dash['total_incidents']} incidents total, "
                f"{dash['critical_incidents']} critical. Organisation trust: {dash['org_trust']}%."}

    return {"answer": "I can help with: 'summarize today's attacks', 'show highest-risk users', "
            "'explain incident 3', 'why was <name> flagged', 'which department is most attacked', "
            "or 'recommend mitigation'."}

@app.post("/api/copilot")
def copilot():
    from flask import request
    data = request.get_json(silent=True) or {}
    q = data.get("question", "")
    if not q.strip():
        return jsonify({"answer": "Ask me about incidents, risky users, attacks by department, or mitigations."})
    return jsonify(_copilot_answer(q))

@app.get("/api/copilot/suggestions")
def copilot_suggestions():
    return jsonify({"suggestions": [
        "Summarize today's attacks",
        "Show highest-risk users",
        "Which department is most attacked?",
        "Explain incident 1",
        "Recommend mitigation",
    ]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
