from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.rootguard.config import CATEGORICAL_FEATURES, MODEL_PATH, NUMERIC_FEATURES, TARGET_COLUMN
from src.rootguard.data import generate_synthetic_incidents, load_sample_data
from src.rootguard.features import validate_features


def evaluate_model(model_name, classifier, preprocessor, x_train, x_test, y_train, y_test):
    pipeline = Pipeline(
        [
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    return {
        "model": model_name,
        "pipeline": pipeline,
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, pos_label="rootkit", zero_division=0),
        "recall": recall_score(y_test, predictions, pos_label="rootkit", zero_division=0),
        "f1_score": f1_score(y_test, predictions, pos_label="rootkit", zero_division=0),
        "predictions": predictions,
    }


def main() -> None:
    data = pd.concat(
        [generate_synthetic_incidents(n_samples=1200, random_state=42), load_sample_data()],
        ignore_index=True,
    )
    x = validate_features(data)
    y = data[TARGET_COLUMN]

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )

    classifiers = [
        (
            "Decision Tree",
            DecisionTreeClassifier(max_depth=10, class_weight="balanced", random_state=42),
        ),
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=250,
                max_depth=12,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=42,
            ),
        ),
        ("Gradient Boosting", GradientBoostingClassifier(random_state=42)),
        (
            "SVM",
            SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42),
        ),
        ("Logistic Regression", LogisticRegression(max_iter=1000, class_weight="balanced")),
        (
            "Stacked Ensemble",
            StackingClassifier(
                estimators=[
                    ("dt", DecisionTreeClassifier(max_depth=10, random_state=42)),
                    ("rf", RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)),
                    ("gb", GradientBoostingClassifier(random_state=42)),
                    ("svm", SVC(kernel="rbf", probability=True, random_state=42)),
                ],
                final_estimator=LogisticRegression(max_iter=1000),
                cv=5,
            ),
        ),
    ]

    evaluated = [
        evaluate_model(name, clf, preprocessor, x_train, x_test, y_train, y_test)
        for name, clf in classifiers
    ]
    results_df = (
        pd.DataFrame(
            [
                {
                    "model": item["model"],
                    "accuracy": item["accuracy"],
                    "precision": item["precision"],
                    "recall": item["recall"],
                    "f1_score": item["f1_score"],
                }
                for item in evaluated
            ]
        )
        .sort_values("accuracy", ascending=False)
        .reset_index(drop=True)
    )

    best_name = results_df.loc[0, "model"]
    best_item = next(item for item in evaluated if item["model"] == best_name)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_item["pipeline"], MODEL_PATH)

    print("DATASET_SHAPE", data.shape)
    print("RESULTS")
    print(results_df.to_string(index=False, float_format=lambda value: f"{value:.4f}"))
    print("BEST_MODEL", best_name)
    print("BEST_ACCURACY", f"{results_df.loc[0, 'accuracy']:.4f}")
    print("CLASSIFICATION_REPORT")
    print(classification_report(y_test, best_item["predictions"], zero_division=0))
    print("SAVED_MODEL", MODEL_PATH)


if __name__ == "__main__":
    main()
