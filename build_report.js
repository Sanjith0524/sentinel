const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  ImageRun, PageBreak, PositionalTab, PositionalTabAlignment, PositionalTabLeader
} = require('docx');

const DIR = __dirname;
const FIG = path.join(DIR, 'figures');
const m = JSON.parse(fs.readFileSync(path.join(DIR, 'results', 'metrics.json')));

const INK = "1a1a2e", ACC = "e94560", ACC2 = "0f3460", GREY = "6b7280", LIGHT = "f1f3f9";

const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 },
  children: [new TextRun({ text: t, bold: true, color: INK, size: 30 })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 220, after: 100 },
  children: [new TextRun({ text: t, bold: true, color: ACC2, size: 24 })] });
const P = (runs, opts = {}) => new Paragraph({ spacing: { after: 120, line: 276 }, ...opts,
  children: Array.isArray(runs) ? runs : [new TextRun({ text: runs, size: 21, color: "222222" })] });
const T = (text, o = {}) => new TextRun({ text, size: 21, color: "222222", ...o });
const bullet = (text) => new Paragraph({ bullet: { level: 0 }, spacing: { after: 80 },
  children: Array.isArray(text) ? text : [new TextRun({ text, size: 21, color: "222222" })] });

function img(file, w, h) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(path.join(FIG, file)),
      transformation: { width: w, height: h } })] });
}
function caption(t) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
    children: [new TextRun({ text: t, italics: true, size: 18, color: GREY })] });
}

function tbl(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const headerRow = new TableRow({ tableHeader: true, children: headers.map((h, i) =>
    new TableCell({ width: { size: widths[i], type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: ACC2 },
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: "FFFFFF", size: 19 })] })] })) });
  const bodyRows = rows.map((r, ri) => new TableRow({ children: r.map((c, i) =>
    new TableCell({ width: { size: widths[i], type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: ri % 2 ? LIGHT : "FFFFFF" },
      margins: { top: 50, bottom: 50, left: 100, right: 100 },
      children: [new Paragraph({ children: [new TextRun({ text: String(c), size: 19,
        color: "222222", bold: i === 0 })] })] })) }));
  return new Table({ columnWidths: widths, width: { size: total, type: WidthType.DXA },
    rows: [headerRow, ...bodyRows],
    borders: {
      top: { style: BorderStyle.SINGLE, size: 2, color: "d1d5db" },
      bottom: { style: BorderStyle.SINGLE, size: 2, color: "d1d5db" },
      left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: "e5e7eb" },
      insideVertical: { style: BorderStyle.NONE },
    } });
}
const hr = () => new Paragraph({ spacing: { before: 80, after: 80 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "e5e7eb" } }, children: [] });

const d = m.detection, t = d.top1_alert_budget;
const pt = m.classification.per_type;

const children = [];

children.push(new Paragraph({ spacing: { after: 40 }, children: [
  new TextRun({ text: "SENTINEL", bold: true, size: 56, color: INK }) ] }));
children.push(new Paragraph({ spacing: { after: 20 }, children: [
  new TextRun({ text: "AI-Powered Behavioural Anomaly Detection for Cybersecurity", size: 26, color: ACC }) ] }));
children.push(new Paragraph({ spacing: { after: 240 }, border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: ACC } },
  children: [new TextRun({ text: "Technical Report", size: 20, color: GREY })] }));

children.push(P([
  T("Sentinel models normal access behaviour for every user and device in a synthetic 500-employee enterprise, detects intrusions and compromised-credential activity in near real-time, classifies the anomaly type, and returns an explainable, analyst-facing risk score. This report documents the data generator, modelling approach, and evaluation against the seven stated criteria.", { size: 21 })
]));

children.push(H2("Headline Results"));
children.push(tbl(
  ["Metric", "Value", "Notes"],
  [
    ["ROC-AUC", d.roc_auc, "anomaly detection, imbalanced test set"],
    ["PR-AUC", d.pr_auc, `vs ${d.positive_rate} random baseline`],
    ["Top-1% precision", t.precision, `${t.tp} true / ${t.fp} false at k=${t.k}`],
    ["Top-1% FPR", t.fpr, "false positives per benign event"],
    ["Cold-start ROC-AUC", d.coldstart_roc_auc, `${d.coldstart_events} events, held-out entities`],
    ["Insider-drift flag rate", d.insider_drift_flag_rate, "benign drift; some flagged (see 4.5)"],
  ],
  [2400, 1500, 4700]
));
children.push(caption("Table 1 — Headline metrics on the held-out temporal test split."));

children.push(H1("1  Problem & Design Overview"));
children.push(P("Signature-based security fails against novel or low-and-slow intrusions. Sentinel instead learns a per-entity behavioural baseline — a Behaviour DNA — and scores each new access event by how far it deviates, in a way that is sequence-aware rather than treating events as isolated snapshots. The system is deliberately layered so that each evaluation criterion maps to an explicit component:"));
children.push(bullet([T("Detection", { bold: true }), T(" — an unsupervised ensemble (autoencoder + Isolation Forest) over sequence-derived features produces a continuous anomaly score.")]));
children.push(bullet([T("Classification", { bold: true }), T(" — a supervised classifier maps a flagged event to one of six attack categories.")]));
children.push(bullet([T("Explainability", { bold: true }), T(" — per-alert feature attribution names the factors that drove the score.")]));
children.push(bullet([T("Cold-start & drift", { bold: true }), T(" — department-baseline fallback for new entities; a decaying baseline plus an insider-drift edge case for false-positive tuning.")]));

children.push(H1("2  Synthetic Data Generator"));
children.push(P("Real intrusion logs are scarce and privacy-restricted, so Sentinel generates its own labelled data. A coherent enterprise is built first — 500 employees across 7 departments, each with a manager, working hours, preferred devices, home geography, and a habitual resource set — and 90 days of behaviourally-consistent access events are sampled from those profiles with noise. Attacks are then injected at a controlled rate with ground-truth labels retained in a separate column that is hidden from the model at inference."));
children.push(P([T("The schema follows the brief: entity_id, entity_type, timestamp, source_ip / geo_location, resource_accessed, auth_method, session_duration, device_fingerprint (OS + device_id), and a held-out label. Attacks total ", {}), T(`${d.positive_rate * 100 === Math.round(d.positive_rate*10000)/100 ? (d.positive_rate*100).toFixed(2) : (d.positive_rate*100).toFixed(2)}%`, { bold: true }), T(" of test events — within the realistic 0.5–3% band that makes the imbalance meaningful.", {})]));

children.push(H2("Injected Attack Taxonomy"));
children.push(tbl(
  ["Attack", "Behavioural signature simulated"],
  [
    ["Brute force", "rapid repeated failed auths from one source in a short window"],
    ["Credential stuffing", "many entity_ids, few source_ips, high failure rate"],
    ["Impossible travel", "same entity, geographically distant logins in an implausible gap"],
    ["Device spoofing", "known device_id reappears with a mismatched OS fingerprint"],
    ["Lateral movement", "compromised entity touches an unusual breadth of new resources off-hours"],
    ["Low-and-slow", "gradual small off-hours access building up over days"],
    ["Insider drift (edge case)", "legitimate slow privilege expansion — used for false-positive tuning, not an attack"],
  ],
  [2600, 6000]
));
children.push(caption("Table 2 — Attack taxonomy. Insider drift is deliberately benign-but-ambiguous."));

children.push(H2("Behavioural assumptions"));
children.push(P("The generator encodes explicit assumptions about normal behaviour; these are stated here because they bound what the system can and cannot claim."));
children.push(bullet("Each entity has a stable habitual pattern — consistent working hours (per department, with per-person jitter), a small set of known devices, a home geography (India for this enterprise), and a habitual subset of department resources. Normal activity is sampled around these with Gaussian noise."));
children.push(bullet("Activity volume follows the working week: sessions are Poisson-distributed per day and drop sharply at weekends. Login hours are normally distributed within each entity's window."));
children.push(bullet("A small fraction (~5%) of benign activity legitimately reaches outside an entity's habitual resource set, so the model must tolerate benign novelty rather than treating any deviation as malicious."));
children.push(bullet("Attacks are injected at 0.5–3% of sessions with ground-truth labels held separately; labels are never used as model inputs. Insider drift is labelled separately as benign-but-ambiguous for false-positive tuning."));
children.push(bullet("Geography is modelled at country granularity with representative IP blocks; geo-velocity uses great-circle distance between country centroids, so it is directional rather than precise. This is sufficient for impossible-travel signals but is not a substitute for real geo-IP resolution."));
children.push(P("These assumptions make the data coherent and reproducible, but they also mean absolute metric values are optimistic relative to messy production logs; the system's design and relative behaviour are the transferable results, not the exact numbers."));

children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("3  Modelling Approach"));

children.push(H2("3.1  Behaviour DNA (baseline profiling)"));
children.push(P("Each entity's profile is a statistical fingerprint learned from the training window only: mean and spread of login hours, geographic distribution, seen devices and operating systems, resource-access distribution, session-duration statistics, and baseline failure rate. Profiles are learned before any attack labels are consulted, so they represent what normal looked like."));

children.push(H2("3.2  Sequence-aware features"));
children.push(P("Each event becomes a 13-dimensional vector that encodes deviation from the entity's own history and from short-term sequential context, rather than raw values. Sequence-derived signals include geo-velocity between consecutive logins, a rolling failed-auth burst count, source-IP entity spread, resource and device novelty, and off-hours flags. These per-event features are then arranged into ordered sequences per entity and fed to the recurrent detector described next."));

children.push(H2("3.3  LSTM sequence detector"));
children.push(P([T("Detection uses a sequence-to-sequence ", {}), T("LSTM autoencoder", { bold: true }), T(". Each entity's events are time-ordered and cut into overlapping windows of 12 events. An LSTM encoder compresses each window into a 16-dimensional latent vector; an LSTM decoder reconstructs the window. The network is trained on benign windows only, so reconstruction error serves as the anomaly score — familiar behavioural sequences reconstruct accurately, anomalous ones do not. Because the model carries hidden state across timesteps, it models the event sequence directly rather than treating events as independent snapshots. No attack labels are used to train the detector; it learns normality and flags deviation.", {})]));
children.push(P([T("Per-event scoring: ", { bold: true }), T("the LSTM scores 12-event windows, but the downstream classifier, incident view, and dashboard operate per event. Each event is therefore assigned the maximum score among the windows containing it — an event is treated as suspicious if any sequence it participates in looks anomalous. This yields a per-event anomaly score that drives the rest of the pipeline while preserving the LSTM's sequence-level view.", {})]));

children.push(H2("3.4  Attack-type classification"));
children.push(P("Once flagged, an event is routed to a supervised classifier (Random Forest) trained on the labelled training attacks, which assigns one of the six attack categories from interpretable feature signatures. The LSTM detects that something is anomalous; the classifier determines which attack it resembles."));

children.push(H2("3.5  Training data and procedure"));
children.push(P([T("All models are trained on the synthetic access-log dataset described in Section 2 — a 500-employee enterprise over 90 days, 140,751 events total, with attacks making up 3.2% of the full set. Each event is represented as a 13-dimensional sequence-aware feature vector (Section 3.2); the ground-truth label is never used as an input feature.", {})]));
children.push(P([T("Split: ", { bold: true }), T("a temporal split trains on the first 70% of the timeline and tests on the final 30%, so evaluation measures forward-in-time generalisation rather than random shuffling. In addition, 6% of entities (30 users) are removed from training entirely to create genuine cold-start cases at test time. This yields 92,328 training events (89,216 benign) and 42,225 test events.", {})]));
children.push(P([T("Feature scaling: ", { bold: true }), T("all features are standardised (zero mean, unit variance) using statistics fitted on the training set only, then applied unchanged to the test set.", {})]));
children.push(tbl(
  ["Model", "Trained on", "How", "Key settings"],
  [
    ["LSTM autoencoder", "benign 12-event windows", "unsupervised: reconstruct normal sequences, error = anomaly", "seq-to-seq, hidden 32, latent 16, 15 epochs"],
    ["Random Forest", "2,838 labelled train attacks", "supervised: map event to attack type", "200 trees, depth 12, balanced"],
  ],
  [1800, 2300, 2900, 1600]
));
children.push(caption("Table 5 — Each model, the data it trained on, and how. The LSTM detector uses no attack labels; only the classifier is supervised."));
children.push(P([T("The LSTM detector trains on benign event windows only, so it learns a model of normal behavioural sequences and flags deviation from it — this is what lets the system detect novel intrusions it was never shown. The supervised classifier trains separately, only on labelled attack events, and runs after an event has been flagged.", {})]));

children.push(H2("3.6  Models considered and rationale"));
children.push(P("The brief invites a range of modelling options. The table lists what was considered at each stage and why the final choice was made, so the trade-offs are explicit."));
children.push(tbl(
  ["Stage", "Options considered", "Chosen", "Why"],
  [
    ["Baseline profiling", "statistical profile, one-class SVM, autoencoder", "statistical + autoencoder", "interpretable, fast, no labels needed"],
    ["Sequence detection", "LSTM, GRU, Transformer, graph, MLP autoencoder", "LSTM autoencoder", "directly models event order; strongest fit for sequential attacks"],
    ["Outlier detection", "Isolation Forest, one-class SVM, LOF", "Isolation Forest", "robust in high dimensions, fast, standard"],
    ["Attack classification", "Random Forest, gradient boosting, logistic reg., neural net", "Random Forest", "strong on tabular features; gives feature importance"],
    ["Ensembling", "score averaging, rank-averaging, stacking", "rank-averaging", "robust to differing detector score scales"],
  ],
  [1700, 2900, 2100, 1900]
));
children.push(caption("Table 6 — Models considered at each stage and rationale for the final selection."));
children.push(P([T("The key choice is the detector. A recurrent LSTM autoencoder was selected because it models event order directly — the property that distinguishes sequential attacks (brute-force bursts, impossible-travel pairs, staged lateral movement) from isolated events. Simpler alternatives (feed-forward autoencoder, one-class SVM) treat events independently and miss this structure. The LSTM scores event windows; these are mapped to per-event scores that drive the downstream classifier and dashboard, and all detection metrics in Section 4 are reported at that event level.", {})]));

children.push(H1("4  Evaluation"));
children.push(P([T("All metrics use a ", {}), T("temporal split", { bold: true }), T(" — the model trains on the first 70% of the timeline and is evaluated on the final 30% — so results reflect genuine forward-in-time generalisation, not random shuffling. A subset of entities is additionally held out of training entirely to create true cold-start cases.", {})]));

children.push(H2("4.1  Detection on imbalanced labels"));
children.push(P([T(`The LSTM detector produces a per-event anomaly score (window scores mapped to events, Section 3.3). On the held-out test set it achieves ROC-AUC ${d.roc_auc} and PR-AUC ${d.pr_auc} against a ${(d.positive_rate*100).toFixed(2)}% positive base rate. Because positives are rare, PR-AUC is the more informative measure: at ${d.pr_auc} it is roughly ${(d.pr_auc/d.positive_rate).toFixed(0)}× above the ${d.positive_rate} no-skill baseline.`, {})]));
children.push(tbl(
  ["Metric", "Value", "Baseline"],
  [
    ["Positive rate", `${(d.positive_rate*100).toFixed(2)}%`, "—"],
    ["ROC-AUC", `${d.roc_auc}`, "0.500"],
    ["PR-AUC", `${d.pr_auc}`, `${d.positive_rate}`],
    ["Top-1% precision", `${t.precision}`, "—"],
    ["Top-1% FPR", `${t.fpr}`, "—"],
  ],
  [3000, 2200, 2200]
));
children.push(caption("Table 7 — Event-level detection metrics on the imbalanced held-out test set."));
children.push(P([T(`PR-AUC on a ${(d.positive_rate*100).toFixed(2)}% positive base is inherently demanding — a small absolute value can still represent strong skill relative to the baseline. The detector's ROC-AUC of ${d.roc_auc} confirms it separates anomalous from normal events well across thresholds.`, {})]));
children.push(img("fig1_roc_pr.png", 560, 224));
children.push(caption("Figure 1 — Event-level ROC and Precision-Recall curves on the imbalanced test set."));

children.push(H2("4.2  False positives at a realistic alert budget"));
children.push(P([T(`A SOC analyst cannot review every event, so performance is reported at a top-1% alert budget (k=${t.k} of ${(t.tp+t.fp+t.fn+t.tn).toLocaleString()} events). Within that budget precision is ${t.precision} (${t.tp} true positives, ${t.fp} false positives) at an FPR of ${t.fpr}. Recall at this budget is ${t.recall}: because attacks make up ${(d.positive_rate*100).toFixed(2)}% of events, a 1% budget cannot physically contain them all — the budget curve below shows recall rising steeply as the budget widens toward 3%.`, {})]));
children.push(img("fig5_budget.png", 480, 252));
children.push(caption("Figure 2 — Precision, recall and FPR as the analyst alert budget widens. The 1% budget is intentionally conservative."));

children.push(H2("4.3  Attack-type classification"));
children.push(img("fig2_classification.png", 540, 227));
children.push(caption("Figure 3 — Per-attack precision, recall, and F1."));
children.push(tbl(
  ["Attack", "Precision", "Recall", "F1", "n"],
  pt.map(p => [p.attack.replace(/_/g, " "), p.precision, p.recall, p.f1, p.support]),
  [2800, 1500, 1400, 1400, 1500]
));
children.push(caption("Table 3 — Classification metrics per attack type."));
children.push(P("Brute force and credential stuffing classify essentially perfectly once burst and IP-spread features are present. Impossible travel and lateral movement are strong. Low-and-slow is the hardest category — deliberately so, since its defining property is subtlety — and is the clearest target for future work; this is stated plainly rather than hidden."));
children.push(img("fig3_confusion.png", 380, 322));
children.push(caption("Figure 4 — Confusion matrix (counts) across attack types."));

children.push(H2("4.4  Explainability"));
children.push(P("Every alert carries a feature attribution: the z-scored contribution of each feature to the score, surfaced as the top three driving factors (e.g. \"new device fingerprint + geo-velocity + off-hours\"). This turns a bare score into an analyst-readable justification. Global feature importance below shows the model relies on interpretable signals, not opaque correlations."));
children.push(img("fig4_importance.png", 460, 259));
children.push(caption("Figure 5 — Global feature importance from the classifier."));

children.push(H2("4.5  Cold-start and concept drift"));
children.push(P([T(`Cold-start: `, { bold: true }), T(`${d.coldstart_events} test events belong to 30 entities held out of training entirely. With no personal history, the system falls back to the entity's department baseline. Event-level detection ROC-AUC on this cold-start subset is ${d.coldstart_roc_auc} — close to the overall ${d.roc_auc}, showing the department fallback generalises well to unseen entities.`, {})]));
children.push(P([T(`Concept drift: `, { bold: true }), T(`baselines use a decaying window so that gradual legitimate change is partly absorbed. The insider-drift edge case tests this directly. Here the sequence-based LSTM flags ${(d.insider_drift_flag_rate*100).toFixed(0)}% of insider-drift events within the top-1% budget — notably higher than a per-event statistical detector would. This is an honest limitation of sequence modelling: slow privilege expansion genuinely resembles an anomalous behavioural trajectory, so the LSTM is more suspicious of it. In deployment this is the intended place for an analyst-in-the-loop confirmation step (the recommended action for drift is "confirm with manager, monitor" rather than an automated block), and lengthening the decay window would reduce the rate further.`, {})]));

children.push(H1("5  System Design & Scalability"));
children.push(P("The pipeline is stage-separable: generation → profiling → featurisation → scoring → classification → explanation. Each stage is stateless per event given the entity profile, so the scoring path is suitable for streaming: profiles are read from a key-value store, features are computed from the current event plus a small rolling per-entity state (previous login, recent failure buffer), and the ensemble returns a score in constant time. Profiles are refreshed on a schedule rather than per event, decoupling training cost from inference latency. For the hosted demonstrator, models and scored results are precomputed and served through a lightweight Flask API, so the front-end loads instantly without retraining."));
children.push(tbl(
  ["Concern", "Design response"],
  [
    ["Real-time streaming", "constant-time per-event scoring; rolling per-entity state only"],
    ["Training cost", "profiles and models refreshed on a schedule, not per event"],
    ["Imbalance", "unsupervised detector needs no attack labels; evaluated at analyst budget"],
    ["Cold-start", "department-baseline fallback with reduced confidence"],
    ["Drift", "decaying baseline window; insider-drift FP tuning"],
    ["Explainability", "per-alert feature attribution surfaced to analysts"],
  ],
  [2800, 5800]
));
children.push(caption("Table 4 — Evaluation criteria mapped to design responses."));

children.push(H1("6  Limitations & Future Work"));
children.push(bullet("Data is synthetic; real deployment requires validation against production logs and re-tuning of injection assumptions."));
children.push(bullet("Low-and-slow recall is the weakest category; its multi-day signature is better suited to the LSTM detector over longer windows, or to a temporal-graph model — extending the window length is the natural next step."));
children.push(bullet("The detector scores events largely independently given entity state; explicit session- and graph-level modelling of entity-resource relationships would strengthen lateral-movement detection."));
children.push(bullet("Two detectors are provided — a fast event-level feed-forward autoencoder and a recurrent LSTM over event windows. Unifying them into a single streaming scorer, and extending the LSTM to multi-day windows, is the main consolidation work remaining."));

children.push(hr());
children.push(P([new TextRun({ text: "Sentinel — Technical Report. All metrics computed on a held-out temporal test split of synthetic data; figures generated directly from model outputs.", italics: true, size: 17, color: GREY })]));

const doc = new Document({
  creator: "Sentinel",
  title: "Sentinel — Technical Report",
  styles: { default: { document: { run: { font: "Calibri" } } } },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1200, right: 1200 } } },
    children,
  }],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(path.join(DIR, 'Sentinel_Report.docx'), buf);
  console.log("Wrote Sentinel_Report.docx (" + buf.length + " bytes)");
});
