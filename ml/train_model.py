import json

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split

from ml.feature_extractor import extract_features


PUBLIC_DATASET = "ml/dataset_public.csv"
TRUSTED_DATASET = "ml/trusted_benign.csv"

MODEL_PATH = "ml/url_threat_model.joblib"
METRICS_PATH = "ml/model_metrics.json"


# =========================================
# 1. LOAD PUBLIC DATASET
# =========================================

print("\nLoading public dataset...")

public_df = pd.read_csv(
    PUBLIC_DATASET
)

public_df = public_df[
    ["url", "label"]
].dropna()

print(
    f"Public dataset rows: {len(public_df)}"
)


# =========================================
# 2. LOAD TRUSTED BENIGN DATASET
# =========================================

print("\nLoading trusted benign dataset...")

trusted_df = pd.read_csv(
    TRUSTED_DATASET
)

# Handle both:
# url,label
# and accidental unnamed columns

trusted_df.columns = [
    str(column).strip().lower()
    for column in trusted_df.columns
]

if "url" not in trusted_df.columns or "label" not in trusted_df.columns:

    trusted_df = pd.read_csv(
        TRUSTED_DATASET,
        header=None,
        names=["url", "label"]
    )

trusted_df = trusted_df[
    ["url", "label"]
].dropna()

trusted_df["label"] = pd.to_numeric(
    trusted_df["label"],
    errors="coerce"
)

trusted_df = trusted_df.dropna(
    subset=["label"]
)

trusted_df["label"] = trusted_df[
    "label"
].astype(int)

print(
    f"Trusted benign rows: {len(trusted_df)}"
)


# =========================================
# 3. COMBINE DATASETS
# =========================================

combined_df = pd.concat(
    [
        public_df,
        trusted_df
    ],
    ignore_index=True
)

combined_df = combined_df.drop_duplicates(
    subset=["url"]
)

print(
    f"\nCombined dataset rows: {len(combined_df)}"
)

print(
    "Class distribution:"
)

print(
    combined_df["label"].value_counts().to_dict()
)


# =========================================
# 4. FEATURE EXTRACTION
# =========================================

print("\nExtracting URL features...")

X = []

y = []

failed_rows = 0

for _, row in combined_df.iterrows():

    try:

        features = extract_features(
            row["url"]
        )

        X.append(features)

        y.append(
            int(row["label"])
        )

    except Exception as error:

        failed_rows += 1

        print(
            f"Feature extraction failed: {row['url']}"
        )

        print(
            f"Error: {error}"
        )


print(
    f"\nFeature matrix shape: "
    f"({len(X)}, {len(X[0])})"
)

print(
    f"Failed rows: {failed_rows}"
)


# =========================================
# 5. TRAIN / TEST SPLIT
# =========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(
    f"\nTraining samples: {len(X_train)}"
)

print(
    f"Testing samples: {len(X_test)}"
)


# =========================================
# 6. RANDOM FOREST MODEL
# =========================================

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(
    X_train,
    y_train
)


# =========================================
# 7. GENERAL MODEL EVALUATION
# =========================================

predictions = model.predict(
    X_test
)

probabilities = model.predict_proba(
    X_test
)[:, 1]


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)

matrix = confusion_matrix(
    y_test,
    predictions
)

report = classification_report(
    y_test,
    predictions,
    target_names=[
        "BENIGN",
        "MALICIOUS"
    ],
    zero_division=0
)


# =========================================
# 8. TRUSTED URL VALIDATION
# =========================================

trusted_features = []

trusted_labels = []

trusted_urls = []

for _, row in trusted_df.iterrows():

    trusted_features.append(
        extract_features(
            row["url"]
        )
    )

    trusted_labels.append(
        int(row["label"])
    )

    trusted_urls.append(
        row["url"]
    )


trusted_predictions = model.predict(
    trusted_features
)

trusted_probabilities = model.predict_proba(
    trusted_features
)[:, 1]


trusted_correct = sum(
    1
    for actual, predicted in zip(
        trusted_labels,
        trusted_predictions
    )
    if actual == predicted
)

trusted_accuracy = (
    trusted_correct /
    len(trusted_labels)
) * 100


# =========================================
# 9. PRINT RESULTS
# =========================================

print("\n=========================================")
print("MODEL EVALUATION")
print("=========================================")

print(
    f"Accuracy : {accuracy:.4f}"
)

print(
    f"Precision: {precision:.4f}"
)

print(
    f"Recall   : {recall:.4f}"
)

print(
    f"F1 Score : {f1:.4f}"
)

print(
    f"ROC-AUC  : {roc_auc:.4f}"
)

print("\nConfusion Matrix:")

print(
    matrix
)

print("\nClassification Report:")

print(
    report
)


print(
    "\n========================================="
)

print(
    "TRUSTED BENIGN VALIDATION"
)

print(
    "========================================="
)

print(
    f"Correct: "
    f"{trusted_correct}/"
    f"{len(trusted_labels)}"
)

print(
    f"Accuracy: "
    f"{trusted_accuracy:.2f}%"
)


print(
    "\nTrusted URL predictions:"
)

for url, prediction, probability in zip(
    trusted_urls,
    trusted_predictions,
    trusted_probabilities
):

    classification = (
        "MALICIOUS"
        if prediction == 1
        else "BENIGN"
    )

    confidence = max(
        probability,
        1 - probability
    ) * 100

    print(
        f"{classification:10} "
        f"{confidence:6.2f}% "
        f"{url}"
    )


# =========================================
# 10. SAVE MODEL
# =========================================

joblib.dump(
    model,
    MODEL_PATH
)

print(
    f"\nModel saved: {MODEL_PATH}"
)


# =========================================
# 11. SAVE METRICS
# =========================================

metrics = {

    "dataset": {

        "public_rows":
            int(len(public_df)),

        "trusted_rows":
            int(len(trusted_df)),

        "combined_rows":
            int(len(combined_df)),

        "failed_rows":
            int(failed_rows)

    },

    "model": {

        "algorithm":
            "RandomForestClassifier",

        "estimators":
            300,

        "features":
            17

    },

    "evaluation": {

        "accuracy":
            round(float(accuracy), 4),

        "precision":
            round(float(precision), 4),

        "recall":
            round(float(recall), 4),

        "f1":
            round(float(f1), 4),

        "roc_auc":
            round(float(roc_auc), 4)

    },

    "trusted_validation": {

        "total":
            len(trusted_labels),

        "correct":
            int(trusted_correct),

        "accuracy_percent":
            round(float(trusted_accuracy), 2)

    },

    "confusion_matrix":
        matrix.tolist()

}


with open(
    METRICS_PATH,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metrics,
        file,
        indent=4
    )


print(
    f"Metrics saved: {METRICS_PATH}"
)

print(
    "\nTraining completed successfully."
)