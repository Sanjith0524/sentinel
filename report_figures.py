import json, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import roc_curve, precision_recall_curve

R = Path(__file__).parent / "results"
FIG = Path(__file__).parent / "figures"; FIG.mkdir(exist_ok=True)
plt.rcParams.update({"font.size": 11, "figure.dpi": 130, "axes.grid": True,
                     "grid.alpha": 0.3, "axes.spines.top": False, "axes.spines.right": False})
INK = "#1a1a2e"; ACC = "#e94560"; ACC2 = "#0f3460"; OK = "#16a34a"

metrics = json.load(open(R / "metrics.json"))
scored = pd.read_parquet(R / "scored_test.parquet")
y = (scored["label"] != "normal").astype(int).values
s = scored["anomaly_score"].values

# 1. ROC + PR curves
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
fpr, tpr, _ = roc_curve(y, s)
ax1.plot(fpr, tpr, color=ACC, lw=2, label=f"ROC (AUC={metrics['detection']['roc_auc']})")
ax1.plot([0,1],[0,1],"--",color="#999",lw=1)
ax1.set_xlabel("False Positive Rate"); ax1.set_ylabel("True Positive Rate")
ax1.set_title("ROC — Anomaly Detection"); ax1.legend(loc="lower right")
prec, rec, _ = precision_recall_curve(y, s)
ax2.plot(rec, prec, color=ACC2, lw=2, label=f"PR (AUC={metrics['detection']['pr_auc']})")
ax2.axhline(y.mean(), ls="--", color="#999", lw=1, label=f"baseline={y.mean():.3f}")
ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision")
ax2.set_title("Precision-Recall — Imbalanced"); ax2.legend(loc="upper right")
plt.tight_layout(); plt.savefig(FIG/"fig1_roc_pr.png", bbox_inches="tight"); plt.close()

# 2. Per-attack-type F1
pt = metrics["classification"]["per_type"]
names = [p["attack"].replace("_"," ").title() for p in pt]
f1s = [p["f1"] for p in pt]; precs=[p["precision"] for p in pt]; recs=[p["recall"] for p in pt]
x = np.arange(len(names)); w=0.26
fig, ax = plt.subplots(figsize=(10,4.2))
ax.bar(x-w, precs, w, label="Precision", color=ACC2)
ax.bar(x, recs, w, label="Recall", color=ACC)
ax.bar(x+w, f1s, w, label="F1", color=OK)
ax.set_xticks(x); ax.set_xticklabels(names, rotation=20, ha="right")
ax.set_ylim(0,1.05); ax.set_ylabel("Score"); ax.set_title("Attack-Type Classification Performance")
ax.legend(ncol=3, loc="lower center"); plt.tight_layout()
plt.savefig(FIG/"fig2_classification.png", bbox_inches="tight"); plt.close()

# 3. Confusion matrix
cm = np.array(metrics["classification"]["confusion_matrix"])
labels = [l.replace("_","\n") for l in metrics["classification"]["labels"]]
fig, ax = plt.subplots(figsize=(6.5,5.5))
cmn = cm / cm.sum(axis=1, keepdims=True).clip(min=1)
im = ax.imshow(cmn, cmap="RdPu", vmin=0, vmax=1)
ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, fontsize=8)
ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=8)
for i in range(len(labels)):
    for j in range(len(labels)):
        ax.text(j,i,cm[i,j],ha="center",va="center",
                color="white" if cmn[i,j]>0.5 else INK, fontsize=9)
ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title("Confusion Matrix (counts)")
plt.colorbar(im, fraction=0.046); plt.tight_layout()
plt.savefig(FIG/"fig3_confusion.png", bbox_inches="tight"); plt.close()

# 4. Feature importance
fi = metrics["feature_importance"]
items = sorted(fi.items(), key=lambda kv: kv[1])
fnames=[k.replace("_"," ") for k,_ in items]; fvals=[v for _,v in items]
fig, ax = plt.subplots(figsize=(8,4.5))
ax.barh(fnames, fvals, color=ACC2); ax.set_xlabel("Importance")
ax.set_title("Feature Importance (classifier)"); plt.tight_layout()
plt.savefig(FIG/"fig4_importance.png", bbox_inches="tight"); plt.close()

# 5. Alert-budget curve: recall & FPR vs budget %
budgets = np.linspace(0.005, 0.10, 40)
order = np.argsort(s)[::-1]
recalls=[]; fprs=[]; precs2=[]
P = y.sum(); N = (y==0).sum()
for b in budgets:
    k = max(1,int(b*len(s))); idx = order[:k]
    fl = np.zeros(len(s),int); fl[idx]=1
    tp=((fl==1)&(y==1)).sum(); fp=((fl==1)&(y==0)).sum()
    recalls.append(tp/P); fprs.append(fp/N); precs2.append(tp/max(1,tp+fp))
fig, ax = plt.subplots(figsize=(8,4.2))
ax.plot(budgets*100, recalls, color=ACC, lw=2, marker="o", ms=3, label="Recall")
ax.plot(budgets*100, precs2, color=OK, lw=2, marker="s", ms=3, label="Precision")
ax.plot(budgets*100, fprs, color=ACC2, lw=2, marker="^", ms=3, label="FPR")
ax.axvline(1.0, ls="--", color="#999", lw=1, label="1% budget")
ax.set_xlabel("Analyst alert budget (% of events)"); ax.set_ylabel("Rate")
ax.set_title("Detection vs Alert Budget"); ax.legend(); plt.tight_layout()
plt.savefig(FIG/"fig5_budget.png", bbox_inches="tight"); plt.close()

print("Saved figures:", [p.name for p in sorted(FIG.glob('*.png'))])
