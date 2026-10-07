from __future__ import annotations

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.rootguard.config import (
    CATEGORICAL_FEATURES,
    MODEL_PATH,
    NUMERIC_FEATURES,
    TARGET_COLUMN,
)
from src.rootguard.features import validate_features


def build_pipeline(random_state: int = 42) -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )

    classifier = RandomForestClassifier(
        n_estimators=250,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=random_state,
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )


def train_model(data: pd.DataFrame, random_state: int = 42) -> tuple[Pipeline, dict[str, object]]:
    if TARGET_COLUMN not in data.columns:
        raise ValueError(f"Training data must contain '{TARGET_COLUMN}'")

    x = validate_features(data)
    y = data[TARGET_COLUMN].astype(str)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=random_state,
        stratify=y,
    )

    pipeline = build_pipeline(random_state=random_state)
    pipeline.fit(x_train, y_train)

    predictions = pipeline.predict(x_test)
    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "classification_report": classification_report(
            y_test,
            predictions,
            output_dict=True,
            zero_division=0,
        ),
    }

    return pipeline, metrics


def save_model(pipeline: Pipeline, path=MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load_model(path=MODEL_PATH) -> Pipeline:
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found at {path}. Run 'python train.py' first."
        )
    return joblib.load(path)
