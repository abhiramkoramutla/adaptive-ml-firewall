import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

FLOW_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smean', 'dmean', 'trans_depth',
    'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
    'ct_srv_dst', 'is_ftp_login', 'is_sm_ips_ports'
]

def load_and_clean_data(filepath):
    print(f"Loading data from {filepath}...")
    if not os.path.exists(filepath):
        print(f"Error: File {filepath} not found.")
        return None, None, [], [], []
        
    try:
        df = pd.read_parquet(filepath)
    except Exception as e:
        print(f"Error reading parquet file: {e}")
        return None, None, [], [], []
    
    label_col = None
    for candidate in ['label', 'Label', 'attack_cat', 'class']:
        if candidate in df.columns:
            label_col = candidate
            break

    y = None
    if label_col:
        y = df[label_col].copy()
    
    DROP_COLS = ['id', 'attack_cat', 'label']
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=cols_to_drop, errors='ignore')

    available = [f for f in FLOW_FEATURES if f in df.columns]
    if not available:
        available = [c for c in df.columns if c.lower() not in ['srcip', 'dstip', 'sport', 'dsport']]
    
    df = df[available].copy()
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()

    for col in numeric_cols:
        median_val = df[col].median() if not df[col].isnull().all() else 0
        df[col] = df[col].fillna(median_val)
        
    for col in categorical_cols:
        mode_val = df[col].mode()[0] if not df[col].mode().empty else 'unknown'
        df[col] = df[col].fillna(mode_val)
        
    return df, y, numeric_cols, categorical_cols, available

def build_and_fit_preprocessor(df, numeric_cols, categorical_cols, save_path="ml_model/preprocessor.pkl"):
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
        
    X_transformed = preprocessor.fit_transform(df)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
    joblib.dump(preprocessor, save_path)
    return preprocessor, X_transformed

_cache = {}

def get_base_dir():
    # Attempt to find project root by looking for ml_model directory
    curr = os.path.dirname(os.path.abspath(__file__))
    while curr != '/' and not os.path.exists(os.path.join(curr, 'ml_model')):
        curr = os.path.dirname(curr)
    return curr

def process_single_packet(packet_features, preprocessor_path=None, schema_path=None):
    global _cache
    
    base_dir = get_base_dir()
    if preprocessor_path is None:
        preprocessor_path = os.path.join(base_dir, "ml_model", "preprocessor.pkl")
    if schema_path is None:
        schema_path = os.path.join(base_dir, "ml_model", "feature_schema.pkl")
    
    try:
        if preprocessor_path not in _cache:
            if not os.path.exists(preprocessor_path):
                return None
            _cache[preprocessor_path] = joblib.load(preprocessor_path)
        if schema_path not in _cache:
            if not os.path.exists(schema_path):
                return None
            _cache[schema_path] = joblib.load(schema_path)
            
        preprocessor = _cache[preprocessor_path]
        schema = _cache[schema_path]
    except Exception as e:
        print(f"Error loading models: {e}")
        return None
        
    df = pd.DataFrame([packet_features])
    
    # Fill missing columns based on schema
    for col in schema.get('numeric_cols', []):
        if col not in df.columns:
            df[col] = 0
            
    for col in schema.get('categorical_cols', []):
        if col not in df.columns:
            df[col] = 'unknown'
            
    # Ensure column order matches training
    all_features = schema.get('all_features', schema.get('numeric_cols', []) + schema.get('categorical_cols', []))
    
    # Only keep features that are actually in the schema to avoid transform errors
    # Filter out features that might have been added by Decision Engine but not in training
    common_features = [f for f in all_features if f in df.columns]
    if len(common_features) < len(all_features):
        # Fill missing features with defaults to match schema shape
        for f in all_features:
            if f not in df.columns:
                df[f] = 0 if f in schema.get('numeric_cols', []) else 'unknown'
    
    df = df[all_features]
    
    X_transformed = preprocessor.transform(df)
    return X_transformed
