# RootGuard

RootGuard is a small production-style security and machine learning project based on AI-powered rootkit detection using stacked machine learning ensembles. The Streamlit app scans uploaded `.txt` or `.log` feature reports and predicts whether the system is `normal` or `rootkit`.

It is designed as a resume-ready project: compact enough to understand quickly, but structured like a real ML codebase with data generation, training, evaluation, inference, tests, and a Streamlit demo.

## Problem

Security teams often review system reports, Linux logs, and tool outputs to check whether a machine may be compromised. RootGuard demonstrates this workflow using binary security flags, numeric system signals, and a stacked ensemble classifier.

The ML workflow predicts one of two classes:

- `normal`
- `rootkit`

## Tech Stack

- Python
- pandas, NumPy
- scikit-learn
- joblib
- Streamlit
- pytest

## Project Structure

```text
.
├── app.py
├── data/
│   └── sample_incidents.csv
├── models/
│   └── .gitkeep
├── notebooks/
│   ├── README.md
│   └── RootGuard_Model_Training.ipynb
├── pyproject.toml
├── requirements.txt
├── src/
│   └── rootguard/
│       ├── __init__.py
│       ├── config.py
│       ├── data.py
│       ├── features.py
│       ├── model.py
│       └── predict.py
├── tests/
│   ├── test_features.py
│   └── test_training.py
└── train.py
```

## Quick Start

Create and activate a virtual environment, then install dependencies.

```bash
pip install -r requirements.txt
```

Train the model.

```bash
python train.py
```

Run a sample prediction.

```bash
python -m src.rootguard.predict --latency-ms 420 --error-rate 8.5 --cpu 72 --memory 64 --recent-deploy true --service checkout --region us-east
```

Launch the demo app.

```bash
streamlit run app.py
```

In the Streamlit app, upload a `.txt` or `.log` file, paste report text, or select one of the sample reports. RootGuard will show:

- whether rootkit risk was detected
- a clean, low, medium, or high risk level
- the suspicious indicators found
- simple explanations for each indicator

Run tests.

```bash
pytest
```

## Notebook

Open `notebooks/RootGuard_Rootkit_Stacked_Ensemble.ipynb` to show the project notebook that matches the rootkit detection topic. It trains each model in a separate section with its own heading, compares accuracy, selects the best model, and saves it.

`notebooks/RootGuard_Separate_Model_Comparison.ipynb` is also available as an earlier separated comparison notebook.

Models compared in the notebook:

- Decision Tree
- Random Forest
- Gradient Boosting
- Support Vector Machine
- Logistic Regression
- Stacked Ensemble

This is a classification project, not regression, because the output is a category/class label.

## Sample Text Files

The `samples/` folder contains mock `.txt` files for the Streamlit upload demo:

- `binary_clean_machine.txt`
- `binary_rootkit_high_risk.txt`
- `binary_rootkit_medium_risk.txt`
- `clean_system_report.txt`
- `clean_developer_machine.txt`
- `threat_hidden_kernel_module.txt`
- `threat_reverse_shell.txt`
- `threat_ld_preload_persistence.txt`
- `threat_log_tampering.txt`
- `suspicious_rootkit_report.txt`

The binary-style sample files use mostly `0` and `1` feature flags, plus numeric values such as `latency_ms`, `suspicious_port_count`, and `failed_login_count`.

## Model

The training pipeline uses:

- `ColumnTransformer` for numeric and categorical preprocessing
- `StandardScaler` for numeric features
- `OneHotEncoder` for categorical features
- `RandomForestClassifier` for root cause classification

The trained artifact is saved to `models/rootguard_pipeline.joblib`.

## Resume Summary

Built **RootGuard**, an end-to-end ML incident triage system that predicts infrastructure incident root causes from telemetry. Implemented data generation, feature preprocessing, model training, evaluation, CLI inference, tests, and an interactive Streamlit demo using Python, scikit-learn, pandas, and joblib.
