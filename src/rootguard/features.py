from __future__ import annotations

import pandas as pd

from src.rootguard.config import CATEGORICAL_FEATURES, FEATURE_COLUMNS, NUMERIC_FEATURES


def validate_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize feature columns for training or inference."""
    missing = sorted(set(FEATURE_COLUMNS) - set(frame.columns))
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    normalized = frame.copy()
    for column in NUMERIC_FEATURES:
        normalized[column] = pd.to_numeric(normalized[column], errors="raise")

    for column in CATEGORICAL_FEATURES:
        normalized[column] = (
            pd.to_numeric(normalized[column], errors="raise")
            .astype(int)
            .clip(lower=0, upper=1)
            .astype(str)
        )

    return normalized[FEATURE_COLUMNS]
