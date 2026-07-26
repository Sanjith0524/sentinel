import numpy as np, pandas as pd, json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (roc_auc_score, average_precision_score,
                             confusion_matrix, precision_recall_fscore_support)

R = Path(__file__).parent / "results"
from profiling_and_features import FEATURE_NAMES

ATTACK_TYPES = ["brute_force", "credential_stuffing", "impossible_travel",
                "device_spoofing", "lateral_movement", "low_and_slow"]

def main():
    ev_path = R / "lstm_event_scored.parquet"
    if not ev_path.exists():
        raise SystemExit("Run lstm_detect.py first (need results/lstm_event_scored.parquet).")

    # LSTM per-event scores + meta
    lstm = pd.read_parquet(ev_path)
    Xtr = np.load(R / "X_train.npy"); Xte = np.load(R / "X_test.npy")
    mtr = pd.read_parquet(R / "meta_train.parquet")
    mte = pd.read_parquet(R / "meta_test.parquet").reset_index(drop=True)

    # align LSTM scores to meta_test row order via event_id
    lstm_idx = lstm.set_index("event_id")["anomaly_score"] if "event_id" in lstm.columns else None
    if lstm_idx is not None:
        score_te = mte["event_id"].map(lstm_idx).fillna(0).values
    else:
        # lstm_event_scored.parquet was written in meta_test order already
        score_te = lstm["anomaly_score"].values
    y_te = (mte["label"] != "normal").astype(int).values

    roc = roc_auc_score(y_te, score_te)
    pr = average_precision_score(y_te, score_te)

    # top-1% event budget
    k = max(1, int(0.01 * len(score_te)))
    top_idx = np.argsort(score_te)[::-1][:k]
    flagged = np.zeros(len(score_te), int); flagged[top_idx] = 1
    tp = int(((flagged==1)&(y_te==1)).sum()); fp = int(((flagged==1)&(y_te==0)).sum())
    fn = int(((flagged==0)&(y_te==1)).sum()); tn = int(((flagged==0)&(y_te==0)).sum())
    fpr_top1 = fp/(fp+tn) if (fp+tn) else 0
    prec_top1 = tp/(tp+fp) if (tp+fp) else 0
    rec_top1 = tp/(tp+fn) if (tp+fn) else 0

    cs = mte["coldstart"].values.astype(bool)
    roc_cs = roc_auc_score(y_te[cs], score_te[cs]) if (cs.sum() and y_te[cs].sum()) else None
    drift_mask = (mte["label"] == "insider_drift").values
    drift_flag_rate = flagged[drift_mask].mean() if drift_mask.sum() else None

    print(f"=== LSTM DETECTION (per-event, {y_te.mean()*100:.2f}% positive) ===")
    print(f"ROC-AUC {roc:.3f}  PR-AUC {pr:.3f}")
    print(f"Top-1%: precision {prec_top1:.3f} recall {rec_top1:.3f} FPR {fpr_top1:.4f}")
    if roc_cs: print(f"Cold-start ROC-AUC {roc_cs:.3f}")

    # ---- classifier (unchanged: RF on labelled train attacks) ----
    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)
    atk_tr = mtr["label"].isin(ATTACK_TYPES).values
    clf = RandomForestClassifier(n_estimators=200, random_state=42,
                                 class_weight="balanced", max_depth=12)
    clf.fit(Xtr_s[atk_tr], mtr["label"].values[atk_tr])
    atk_te = mte["label"].isin(ATTACK_TYPES).values
    pred_te = clf.predict(Xte_s[atk_te]); true_te = mte["label"].values[atk_te]
    p, r, f, s = precision_recall_fscore_support(true_te, pred_te, labels=ATTACK_TYPES, zero_division=0)
    per_type = [{"attack": t, "precision": round(float(p[i]),3), "recall": round(float(r[i]),3),
                 "f1": round(float(f[i]),3), "support": int(s[i])} for i, t in enumerate(ATTACK_TYPES)]
    for pt in per_type:
        print(f"  {pt['attack']:22s} P={pt['precision']:.2f} R={pt['recall']:.2f} F1={pt['f1']:.2f}")
    cm = confusion_matrix(true_te, pred_te, labels=ATTACK_TYPES)
    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_.round(3).tolist()))

    results = {
        "detector": "LSTM autoencoder (per-event via window-max aggregation)",
        "detection": {
            "roc_auc": round(float(roc),3), "pr_auc": round(float(pr),3),
            "positive_rate": round(float(y_te.mean()),4),
            "top1_alert_budget": {"k": int(k), "precision": round(prec_top1,3),
                "recall": round(rec_top1,3), "fpr": round(fpr_top1,4),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "coldstart_roc_auc": round(float(roc_cs),3) if roc_cs else None,
            "coldstart_events": int(cs.sum()),
            "insider_drift_flag_rate": round(float(drift_flag_rate),3) if drift_flag_rate is not None else None,
        },
        "classification": {"per_type": per_type, "confusion_matrix": cm.tolist(), "labels": ATTACK_TYPES},
        "feature_importance": importances,
    }
    json.dump(results, open(R/"metrics.json","w"), indent=2)  # overwrite: LSTM is now THE model

    # scored test set for dashboard/incidents (same schema as detect.py)
    mte2 = mte.copy()
    mte2["anomaly_score"] = score_te
    mte2["flagged_top1"] = flagged
    pred_all = clf.predict(Xte_s)
    mte2["predicted_type"] = np.where(flagged==1, pred_all, "")
    mte2.to_parquet(R/"scored_test.parquet")

    mu, sd = Xte.mean(0), Xte.std(0)+1e-9
    z = (Xte - mu)/sd
    att = []
    for idx in top_idx:
        contrib = {FEATURE_NAMES[j]: round(float(z[idx,j]),2) for j in range(len(FEATURE_NAMES))}
        top3 = sorted(contrib.items(), key=lambda kv:-abs(kv[1]))[:3]
        att.append({"event_id": mte2.iloc[idx]["event_id"], "top_factors": top3, "all": contrib})
    json.dump(att, open(R/"attributions.json","w"), indent=2)
    print("\nSaved metrics.json (LSTM), scored_test.parquet, attributions.json")

if __name__ == "__main__":
    main()
