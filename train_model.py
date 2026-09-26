import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# --------------------------------------------------
# 1. Load dataset
# --------------------------------------------------

DATASET_PATH = "dataset/phishing_dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully.")
print("Dataset shape:", df.shape)


# --------------------------------------------------
# 2. Separate features and target
# --------------------------------------------------

# Remove ID because it has no useful predictive meaning
X = df.drop(columns=["id", "CLASS_LABEL"])

# Target
y = df["CLASS_LABEL"]

print("\nNumber of features:", X.shape[1])
print("Target distribution:")
print(y.value_counts())


# --------------------------------------------------
# 3. Split dataset
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 4. Create Random Forest model
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)


# --------------------------------------------------
# 5. Train model
# --------------------------------------------------

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training completed.")


# --------------------------------------------------
# 6. Make predictions
# --------------------------------------------------

y_pred = model.predict(X_test)


# --------------------------------------------------
# 7. Evaluate model
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n======================================")
print("MODEL EVALUATION")
print("======================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# --------------------------------------------------
# 8. Save model
# --------------------------------------------------

MODEL_PATH = "phishing_model.pkl"

joblib.dump(
    {
        "model": model,
        "features": X.columns.tolist()
    },
    MODEL_PATH
)

print("\n======================================")
print("MODEL SAVED")
print("======================================")

print("Saved as:", MODEL_PATH)
print("Number of saved features:", len(X.columns))