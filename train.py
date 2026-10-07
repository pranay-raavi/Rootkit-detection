from __future__ import annotations

import json

import pandas as pd

from src.rootguard.config import MODEL_PATH
from src.rootguard.data import generate_synthetic_incidents, load_sample_data
from src.rootguard.model import save_model, train_model


def main() -> None:
    synthetic_data = generate_synthetic_incidents(n_samples=1200, random_state=42)
    try:
        sample_data = load_sample_data()
        training_data = pd.concat([synthetic_data, sample_data], ignore_index=True)
    except FileNotFoundError:
        training_data = synthetic_data

    model, metrics = train_model(training_data, random_state=42)
    save_model(model, MODEL_PATH)

    print(f"Saved model to: {MODEL_PATH}")
    print(json.dumps({"accuracy": metrics["accuracy"]}, indent=2))


if __name__ == "__main__":
    main()
