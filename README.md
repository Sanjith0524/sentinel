# Sentinel — AI Behavioural Anomaly Detection for Cybersecurity

Models normal access behaviour per user/device, detects intrusions with a
sequence-aware LSTM, classifies the attack type, and presents an explainable,
analyst-facing SOC dashboard.

## Files → Deliverables

| File | Deliverable | Model / role |
|------|-------------|--------------|
| `data_generator.py` | 1. Synthetic data generator | Builds the enterprise + injects labelled attack taxonomy |
| `profiling_and_features.py` | 2. Baseline profiling model | Per-entity "Behaviour DNA" statistical profile + sequence-aware feature engineering |
| `lstm_detector.py` | 3. Detection model (sequence-aware) | **LSTM autoencoder** — the detector |
| `classifier.py` | 4. Anomaly classification | Random Forest attack-type classifier + runs LSTM-driven detection metrics |
| `dashboard_data.py` | 5 & 6. Explainability + dashboard data | Builds incidents, narratives, feature attribution, threat-memory correlations |
| `api/` + `frontend/` | 6. Analyst dashboard | Flask API + React SOC dashboard (incl. AI Security Copilot) |
| `report_figures.py` + `build_report.js` | 7. Report | Figures + Word report generator |
| `Sentinel_Report.docx` | 7. Report | The generated report (event-level LSTM metrics) |

## Run order

```bash
# 1. environment
python3 -m venv venv && source venv/bin/activate
pip install numpy pandas scikit-learn faker pyarrow matplotlib torch

# 2. pipeline (in order)
python data_generator.py            # -> data/events.parquet, entities.json
python profiling_and_features.py    # -> profiles + X_train/X_test + meta
python lstm_detector.py             # -> LSTM per-event scores (needs torch)
python classifier.py                # -> metrics.json, scored_test.parquet, attributions.json
python dashboard_data.py            # -> app_data.json (incidents, threat memory)
python report_figures.py            # -> figures/*.png
node build_report.js                # -> Sentinel_Report.docx  (needs: npm install docx)

# 3. app (two terminals)
cd api && pip install -r requirements.txt && python app.py     # backend :5001
cd frontend && npm install && npm run dev                      # frontend :5173
```

## Detector configuration (as reported)

LSTM autoencoder: 12-event windows, hidden 32, latent 16, 15 epochs, max window→event
aggregation. Event-level metrics: ROC-AUC 0.905, PR-AUC 0.353, top-1% precision 0.581,
cold-start ROC-AUC 0.914. These are the numbers in Sentinel_Report.docx.

## Note on the app path
In `api/app.py`, the results path uses `Path(__file__).resolve().parent.parent`.
Run `python app.py` from inside `api/`.

## IMPORTANT — regenerate on your machine
This bundle ships the trained pipeline's inputs and the report, but a few
generated files (scored_test.parquet, attributions.json, app_data.json) and the
figure PNGs must be regenerated from your real LSTM run, because PyTorch does not
run in the build environment. After `pip install torch`, run the pipeline in the
order above. The dashboard needs `app_data.json`, so run `dashboard_data.py`
before starting the app.
