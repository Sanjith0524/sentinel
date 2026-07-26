import numpy as np, pandas as pd, json
from pathlib import Path

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    raise SystemExit(
        "PyTorch not installed. Run:  pip install torch\n"
        "(CPU build is fine; this trains in a few minutes on a laptop.)")

R = Path(__file__).parent / "results"
M = Path(__file__).parent / "models"; M.mkdir(exist_ok=True)
DATA = Path(__file__).parent / "data"

torch.manual_seed(42); np.random.seed(42)

SEQ_LEN = 12          # events per window
STRIDE = 6            # overlap between windows
BATCH = 128
EPOCHS = 15
HIDDEN = 32
LATENT = 16
LR = 1e-3

# ---------------------------------------------------------------------------
# Load the SAME sequence-aware features we already engineered, but now we feed
# them to the LSTM as ordered sequences per entity (the LSTM adds temporal
# modelling ON TOP of the per-event features).
# ---------------------------------------------------------------------------
from profiling_and_features import (load, temporal_split, build_profiles, build_dept_profiles,
                      featurize, FEATURE_NAMES)

def build_windows(X, meta):

    n_feat = X.shape[1]
    windows, wlabels, wcold, went, widx = [], [], [], [], []
    meta = meta.reset_index(drop=True)
    for eid, idx in meta.groupby("entity_id").groups.items():
        idx = list(idx)
        if len(idx) < SEQ_LEN:
            # pad short entities by repeating last event
            pad = idx + [idx[-1]] * (SEQ_LEN - len(idx))
            chunks = [pad]
        else:
            chunks = [idx[i:i+SEQ_LEN] for i in range(0, len(idx)-SEQ_LEN+1, STRIDE)]
        for ch in chunks:
            windows.append(X[ch])
            lbls = meta.loc[ch, "label"].values
            wlabels.append(int((lbls != "normal").any()))
            wcold.append(bool(meta.loc[ch, "coldstart"].any()))
            went.append(eid)
            widx.append(ch)
    return (np.array(windows, dtype=np.float32), np.array(wlabels),
            np.array(wcold), np.array(went), widx)

# ---------------------------------------------------------------------------
class LSTMAutoencoder(nn.Module):
    def __init__(self, n_feat, hidden=HIDDEN, latent=LATENT):
        super().__init__()
        self.encoder = nn.LSTM(n_feat, hidden, batch_first=True)
        self.to_latent = nn.Linear(hidden, latent)
        self.from_latent = nn.Linear(latent, hidden)
        self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, n_feat)

    def forward(self, x):
        B, T, F = x.shape
        _, (h, _) = self.encoder(x)          # h: [1, B, hidden]
        z = self.to_latent(h[-1])            # [B, latent]
        dec_in = self.from_latent(z).unsqueeze(1).repeat(1, T, 1)  # seed each step
        dec_out, _ = self.decoder(dec_in)
        return self.out(dec_out)             # [B, T, F]

def recon_error(model, X):
    model.eval()
    errs = []
    with torch.no_grad():
        for i in range(0, len(X), 512):
            xb = torch.from_numpy(X[i:i+512])
            pred = model(xb)
            e = ((pred - xb) ** 2).mean(dim=(1, 2)).cpu().numpy()
            errs.append(e)
    return np.concatenate(errs)

# ---------------------------------------------------------------------------
def main():
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import roc_auc_score, average_precision_score

    df, entities = load()
    train, test, cutoff, cold = temporal_split(df)
    profiles = build_profiles(train)
    dept_profiles, ent_dept = build_dept_profiles(train, entities)
    Xtr, mtr = featurize(train, profiles, dept_profiles, ent_dept, True)
    Xte, mte = featurize(test, profiles, dept_profiles, ent_dept, False)

    scaler = StandardScaler().fit(Xtr)
    Xtr, Xte = scaler.transform(Xtr).astype(np.float32), scaler.transform(Xte).astype(np.float32)

    Wtr, ytr, ctr, etr, itr = build_windows(Xtr, mtr)
    Wte, yte, cte, ete, ite = build_windows(Xte, mte)
    print(f"Train windows: {Wtr.shape}  Test windows: {Wte.shape}")
    print(f"Test window anomaly rate: {yte.mean()*100:.2f}%")

    # train on BENIGN windows only
    benign = Wtr[ytr == 0]
    print(f"Training LSTM autoencoder on {len(benign):,} benign windows…")
    model = LSTMAutoencoder(Wtr.shape[2])
    opt = torch.optim.Adam(model.parameters(), lr=LR)
    lossf = nn.MSELoss()
    ds = DataLoader(TensorDataset(torch.from_numpy(benign)), batch_size=BATCH, shuffle=True)
    for ep in range(EPOCHS):
        model.train(); tot = 0
        for (xb,) in ds:
            opt.zero_grad()
            loss = lossf(model(xb), xb)
            loss.backward(); opt.step()
            tot += loss.item() * len(xb)
        if (ep+1) % 3 == 0 or ep == 0:
            print(f"  epoch {ep+1:2d}/{EPOCHS}  loss {tot/len(benign):.4f}")

    score_te = recon_error(model, Wte)
    roc = roc_auc_score(yte, score_te)
    pr = average_precision_score(yte, score_te)

    # top-1% window budget
    k = max(1, int(0.01 * len(score_te)))
    order = np.argsort(score_te)[::-1]
    fl = np.zeros(len(score_te), int); fl[order[:k]] = 1
    tp = int(((fl==1)&(yte==1)).sum()); fp = int(((fl==1)&(yte==0)).sum())
    fn = int(((fl==0)&(yte==1)).sum()); tn = int(((fl==0)&(yte==0)).sum())
    fpr = fp/(fp+tn) if (fp+tn) else 0
    prec = tp/(tp+fp) if (tp+fp) else 0

    # cold-start windows
    roc_cs = None
    if cte.sum() and yte[cte].sum():
        roc_cs = roc_auc_score(yte[cte], score_te[cte])

    print(f"\n=== LSTM AUTOENCODER (window-level, {yte.mean()*100:.2f}% positive) ===")
    print(f"ROC-AUC: {roc:.3f}   PR-AUC: {pr:.3f}")
    print(f"Top-1% window budget: precision {prec:.3f}, FPR {fpr:.4f}")
    if roc_cs: print(f"Cold-start windows ROC-AUC: {roc_cs:.3f}")

    # ---- Map window scores back to PER-EVENT scores ----
    # Aggregation choice matters a lot for event-level precision. MAX lets a
    # single anomalous window drag benign neighbours up (hurts precision); MEAN
    # and MEDIAN are smoother. Set AGG below to "mean", "median", or "max".
    AGG = "mean"
    n_events = len(mte)
    per_event_scores = [[] for _ in range(n_events)]
    for w, rows in enumerate(ite):
        for r in rows:
            per_event_scores[r].append(score_te[w])
    event_score = np.zeros(n_events)
    for r in range(n_events):
        vals = per_event_scores[r]
        if not vals:
            event_score[r] = 0.0
        elif AGG == "max":
            event_score[r] = max(vals)
        elif AGG == "median":
            event_score[r] = float(np.median(vals))
        else:  # mean
            event_score[r] = float(np.mean(vals))
    print(f"Window->event aggregation: {AGG}")
    # rank-normalise per-event score to 0-1 (matches downstream scale)
    ev_rank = np.argsort(np.argsort(event_score)) / (n_events - 1 + 1e-9)

    mte_out = mte.reset_index(drop=True).copy()
    mte_out["anomaly_score"] = ev_rank
    # top-1% event budget flag (matches detect.py convention)
    ke = max(1, int(0.01 * n_events))
    ev_top = np.argsort(ev_rank)[::-1][:ke]
    flagged = np.zeros(n_events, int); flagged[ev_top] = 1
    mte_out["flagged_top1"] = flagged
    # per-event ground truth for reference
    y_event = (mte_out["label"] != "normal").astype(int).values
    roc_event = roc_auc_score(y_event, ev_rank)
    pr_event = average_precision_score(y_event, ev_rank)
    tp_e = int(((flagged==1)&(y_event==1)).sum()); fp_e = int(((flagged==1)&(y_event==0)).sum())
    fn_e = int(((flagged==0)&(y_event==1)).sum()); tn_e = int(((flagged==0)&(y_event==0)).sum())
    print(f"\n=== LSTM mapped to PER-EVENT ({y_event.mean()*100:.2f}% positive) ===")
    print(f"Event-level ROC-AUC: {roc_event:.3f}  PR-AUC: {pr_event:.3f}")
    print(f"Top-1% event budget: precision {tp_e/max(1,tp_e+fp_e):.3f}, "
          f"FPR {fp_e/max(1,fp_e+tn_e):.4f}")
    # save per-event scores for the downstream pipeline (detect.py reads this)
    mte_out.to_parquet(R/"lstm_event_scored.parquet")

    out = {
        "model": "LSTM autoencoder (sequence-to-sequence)",
        "window_len": SEQ_LEN, "hidden": HIDDEN, "latent": LATENT, "epochs": EPOCHS,
        "roc_auc": round(float(roc),3), "pr_auc": round(float(pr),3),
        "window_positive_rate": round(float(yte.mean()),4),
        "top1": {"precision": round(prec,3), "fpr": round(fpr,4),
                 "tp": tp, "fp": fp, "fn": fn, "tn": tn, "k": int(k)},
        "coldstart_roc_auc": round(float(roc_cs),3) if roc_cs else None,
        "event_level": {
            "roc_auc": round(float(roc_event),3), "pr_auc": round(float(pr_event),3),
            "positive_rate": round(float(y_event.mean()),4),
            "top1": {"precision": round(tp_e/max(1,tp_e+fp_e),3),
                     "fpr": round(fp_e/max(1,fp_e+tn_e),4),
                     "tp": tp_e, "fp": fp_e, "fn": fn_e, "tn": tn_e, "k": int(ke)},
        },
    }
    json.dump(out, open(R/"lstm_metrics.json","w"), indent=2)
    pd.DataFrame({"entity_id": ete, "anomaly_score": score_te,
                  "label_anomaly": yte, "coldstart": cte}).to_parquet(R/"lstm_scored.parquet")
    torch.save(model.state_dict(), M/"lstm_ae.pt")
    print(f"\nSaved lstm_metrics.json, lstm_scored.parquet, lstm_event_scored.parquet, models/lstm_ae.pt")

if __name__ == "__main__":
    main()
