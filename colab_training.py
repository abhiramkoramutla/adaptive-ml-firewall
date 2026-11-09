# ============================================================
# ADAPTIVE AI FIREWALL — GOOGLE COLAB TRAINING SCRIPT
# Dataset: UNSW-NB15 (.parquet)
# Algorithm: Isolation Forest
# ============================================================
# Run this cell-by-cell in Google Colab
# ============================================================

# ── CELL 1: Install dependencies ──────────────────────────
# !pip install pyarrow fastparquet scikit-learn pandas numpy matplotlib seaborn joblib

# ── CELL 2: Imports ───────────────────────────────────────
import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report, confusion_matrix


# ── CELL 3: Load dataset from local path ─────────────────
filename = os.getenv("DATASET_PATH", "UNSW_NB15_training-set.parquet")
if not os.path.exists(filename):
    print(f"[*] Fallback: Dataset not found at {filename}")
    # Try common fallback paths
    for candidate in [
        "model/UNSW_NB15_training-set.parquet",
        "ml_model/UNSW_NB15_training-set.parquet",
    ]:
        if os.path.exists(candidate):
            filename = candidate
            break
    if not os.path.exists(filename):
        print("[!] Warning: Dataset file not found in common locations.")

if os.path.exists(filename):
    df = pd.read_parquet(filename)
    print(f"Dataset shape: {df.shape}")
    print("\nColumn names:")
    print(df.columns.tolist())
    print("\nFirst 5 rows:")
    df.head()
else:
    df = pd.DataFrame() # Empty fallback
    print("Dataset not loaded.")

# ── CELL 4: Inspect dataset ───────────────────────────────
if not df.empty:
    print("=== Data Types ===")
    print(df.dtypes)
    print("\n=== Missing Values ===")
    print(df.isnull().sum())
    print("\n=== Basic Stats ===")
    df.describe()

# ── CELL 5: Drop irrelevant columns ───────────────────────
# Columns to drop (IDs, labels for unsupervised, low-info cols)
DROP_COLS = ['id', 'attack_cat', 'label']  # adjust if column names differ

# Store label for evaluation if exists
label_col = None
if not df.empty:
    for candidate in ['label', 'Label', 'attack_cat', 'class']:
        if candidate in df.columns:
            label_col = candidate
            break

if label_col:
    y = df[label_col].copy()
    print(f"Label column found: '{label_col}'")
    print(f"Label distribution:\n{y.value_counts()}")
else:
    y = None
    print("No label column found — fully unsupervised mode")

# Drop known irrelevant columns (only if they exist)
if not df.empty:
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=cols_to_drop, errors='ignore')
    print(f"\nDropped columns: {cols_to_drop}")
    print(f"Remaining shape: {df.shape}")

# ── CELL 6: Feature selection — flow-based features ───────
# UNSW-NB15 flow-relevant features
FLOW_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smean', 'dmean', 'trans_depth',
    'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
    'ct_srv_dst', 'is_ftp_login', 'is_sm_ips_ports'
]

# Only keep features that exist in dataset
if not df.empty:
    available = [f for f in FLOW_FEATURES if f in df.columns]
    df = df[available].copy()
    print(f"\nSelected {len(available)} flow features")

# ── CELL 7: Handle missing values ─────────────────────────
if not df.empty:
    # Identify numeric and categorical columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()

    # Fill numeric missing with median
    for col in numeric_cols:
        median_val = df[col].median()
        df[col] = df[col].fillna(median_val)

    # Fill categorical missing with mode
    for col in categorical_cols:
        mode_val = df[col].mode()[0] if not df[col].mode().empty else 'unknown'
        df[col] = df[col].fillna(mode_val)

    print(f"\nMissing values after imputation: {df.isnull().sum().sum()}")

# ── CELL 8: Correlation heatmap (numeric only) ────────────
if not df.empty and len(numeric_cols) > 1:
    plt.figure(figsize=(16, 12))
    corr = df[numeric_cols].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, cmap='coolwarm', center=0,
                square=True, linewidths=0.5, cbar_kws={"shrink": 0.5},
                annot=False, fmt='.2f')
    plt.title('Feature Correlation Heatmap', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig('correlation_heatmap.png', dpi=150, bbox_inches='tight')
    plt.show()

# ── CELL 9: Build preprocessing pipeline ──────────────────
if not df.empty:
    numeric_transformer = StandardScaler()
    if categorical_cols:
        categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        preprocessor = ColumnTransformer(transformers=[
            ('num', numeric_transformer, numeric_cols),
            ('cat', categorical_transformer, categorical_cols)
        ])
    else:
        preprocessor = ColumnTransformer(transformers=[
            ('num', numeric_transformer, numeric_cols)
        ])
    
    # Store feature schema for deployment
    feature_schema = {
        'numeric_cols': numeric_cols,
        'categorical_cols': categorical_cols,
        'all_features': available
    }
    joblib.dump(feature_schema, 'feature_schema.pkl')

# ── CELL 10: Fit preprocessor and transform data ──────────
if not df.empty:
    X_transformed = preprocessor.fit_transform(df)
    print(f"Transformed shape: {X_transformed.shape}")

# ── CELL 11: Tune contamination ───────────────────────────
if not df.empty:
    if y is not None:
        y_binary = (y != 0).astype(int)
        attack_ratio = y_binary.mean()
        contamination = float(np.clip(attack_ratio, 0.01, 0.45))
    else:
        contamination = 0.05

# ── CELL 12: Train Isolation Forest ───────────────────────
if not df.empty:
    if y is not None:
        y_binary = (y != 0).astype(int)
        normal_mask = (y_binary == 0)
        X_train = X_transformed[normal_mask]
    else:
        X_train = X_transformed

    model = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1
    )
    model.fit(X_train)

# ── CELL 13: Anomaly score distribution ───────────────────
if not df.empty:
    scores = model.decision_function(X_transformed)
    predictions = model.predict(X_transformed)

# ── CELL 14: Evaluation metrics (if labels exist) ─────────
if y is not None and not df.empty:
    y_binary = (y != 0).astype(int)
    y_pred = (predictions == -1).astype(int)
    print("=== Classification Report ===")
    print(classification_report(y_binary, y_pred, target_names=['Normal', 'Attack']))

# ── CELL 15: Save model and preprocessor ──────────────────
if not df.empty:
    joblib.dump(model, 'model.pkl')
    joblib.dump(preprocessor, 'preprocessor.pkl')
    print("\n✅ model.pkl saved locally")

# ── CELL 16: Download files (COMMENTED OUT FOR LOCAL RUN) ──
# try:
#     from google.colab import files
#     files.download('model.pkl')
#     files.download('preprocessor.pkl')
#     files.download('feature_schema.pkl')
# except ImportError:
#     print("\nGoogle Colab 'files' module not found – skipping download step.")
print("\nTraining complete. Files saved in current directory.")
