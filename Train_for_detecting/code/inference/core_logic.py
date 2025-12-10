import os
import json
import time
import pickle
import logging
import requests
import re
import sys
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor

# --- IMPORT PATHS ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from utils.paths import get_base_dir
from utils.helpers import (
    canonical_no_space, apply_temperature_scaling, 
    get_value_from_aliases, PROTOCOL_MAP
)

# =================== CONFIG & SETUP ===================
BASE_DIR = get_base_dir()
MODEL_DIR = os.path.join(BASE_DIR, "models")
DOC_DIR = os.path.join(BASE_DIR, "documentation")

MODEL_FILE = "LightGBM_model.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_MAP_FILE = "label_mapping.pkl"
FEATURE_FILE = "selected_features.txt"

ALERT_DIR = os.path.join(DOC_DIR, "alerts")
DEBUG_DIR = os.path.join(DOC_DIR, "debug_payloads")
LOKI_INPUT_DIR = os.path.join(DOC_DIR, "loki_inputs")

for d in [ALERT_DIR, DEBUG_DIR, LOKI_INPUT_DIR]:
    os.makedirs(d, exist_ok=True)

# --- RUNTIME CONFIG ---
SAVE_DEBUG = True
ENABLE_LLM = False 
ENABLE_LOKI = True
BENIGN_INTERVAL = 60
benign_last_ts = 0.0

# --- THRESHOLDS ---
FILTER_CONFIDENCE_THRESHOLD = 0.50 
BENIGN_RATIO_THRESHOLD = 0.90
DDOS_MIN_UNIQUE_IPS = 2  

# --- SERVICE IP CONFIG ---
IP_LLM = "<>"
IP_LOKI = "<>"
VLLM_URL = "<>"
VLLM_API_KEY = "<>"
LOKI_PUSH = "<>"

io_executor = ThreadPoolExecutor(max_workers=5)

# =================== LOAD RESOURCES ===================
logging.info("Loading model resources...")
try:
    with open(os.path.join(MODEL_DIR, MODEL_FILE), "rb") as f:
        model_obj = pickle.load(f)
    model = model_obj["model"] if isinstance(model_obj, dict) and "model" in model_obj else model_obj
    
    features = model_obj.get("features", []) if isinstance(model_obj, dict) else []
    if not features:
        with open(os.path.join(MODEL_DIR, FEATURE_FILE), "r") as f:
            features = [line.strip() for line in f if line.strip()]
            
    with open(os.path.join(MODEL_DIR, SCALER_FILE), "rb") as f: scaler = pickle.load(f)
    with open(os.path.join(MODEL_DIR, LABEL_MAP_FILE), "rb") as f: label_mapping = pickle.load(f)
    
    id_to_label = {v: k for k, v in label_mapping.items()}
    feature_alias = {canonical_no_space(f): f for f in features}
    logging.info(f"[+] Loaded successfully. {len(features)} features.")
except Exception as e:
    logging.error(f"[!] CRITICAL ERROR LOADING MODEL: {e}")
    raise e

# =================== HELPER FUNCTIONS ===================
def save_json(folder, prefix, data):
    ts = int(time.time())
    with open(os.path.join(folder, f"{prefix}_{ts}.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# =================== CORE PREDICTION ===================
def predict_single_flow(payload):
    remapped = {}
    for k, v in payload.items():
        key = canonical_no_space(k)
        if key in feature_alias: remapped[feature_alias[key]] = v
            
    df = pd.DataFrame([remapped]).reindex(columns=features, fill_value=0)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    
    try:
        X_scaled = pd.DataFrame(scaler.transform(df[features].astype(np.float32)), columns=features)
        raw_probs = model.predict_proba(X_scaled)[0]
        scaled_probs = apply_temperature_scaling(raw_probs, temperature=1.5)
        
        max_idx = np.argmax(scaled_probs)
        pred_id = model.classes_[max_idx] if hasattr(model, "classes_") else max_idx
            
        label = id_to_label.get(int(pred_id), "Unknown")
        conf = round(float(scaled_probs[max_idx]), 3)
        return label, conf
    except Exception as e:
        logging.error(f"Prediction Error: {e}")
        return "Error", 0.0

def extract_flow_metadata(payload):
    common_proto_keys = ["Protocol", "proto", "protocol_name", "nw_proto", "L4_PROTO", "ip_proto"]
    src = get_value_from_aliases(payload, ["src_ip", "src_addr", "Source IP", "src"], "0.0.0.0")
    dst = get_value_from_aliases(payload, ["dst_ip", "dst_addr", "Destination IP", "dst"], "0.0.0.0")
    raw_port = get_value_from_aliases(payload, ["dst_port", "Destination Port", "dport"], 0)
    try: port = int(raw_port)
    except: port = 0
    
    raw_proto = get_value_from_aliases(payload, common_proto_keys, None)
    if raw_proto is None:
        proto_str = "TCP" 
    else:
        try:
            proto_int = int(raw_proto)
            proto_str = PROTOCOL_MAP.get(proto_int, str(proto_int))
        except (ValueError, TypeError):
            proto_str = str(raw_proto).upper()
    return src, dst, port, proto_str

# =================== IO LOGIC ===================
def push_to_loki(event_json):
    payload = {
        "streams": [
            {
                "stream": {
                    "job": "llm_gateway", 
                    "attack_type": event_json.get("attack_type", "generic")
                }, 
                "values": [[str(int(time.time()*1e9)), json.dumps(event_json, ensure_ascii=False)]]
            }
        ]
    }
    try: requests.post(LOKI_PUSH, json=payload, timeout=2)
    except Exception as e: logging.error(f"Loki Error: {e}")

def handle_alert_io_task(alert):
    try:
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert["window_end"]))
        reasoning = "N/A"
        solution = "N/A"
        
        clean_subtype = re.sub(r'(?i)\b(ddos|dos)_?', '', alert["label"]).strip("_") or "Generic"
        
        src_ips = alert["src_ip_list"]
        if len(src_ips) == 1:
            src_ip_display = src_ips[0]
        else:
            src_ip_display = str(src_ips[:5]) + (f" (+{len(src_ips)-5} others)" if len(src_ips) > 5 else "")
            src_ip_display = src_ip_display.replace("'", "").replace("[", "").replace("]", "")

        event_json = {
            "timestamp": ts_str,
            "src_ip": src_ip_display,       
            "dst_ip": alert["dst_ip"],      
            "protocol": str(alert["protocol"]),
            "dst_port": int(alert["dst_port"]),
            "attack_type": alert["subtype"],
            "attack_subtype": clean_subtype,      
            "confidence": alert["avg_conf"],
            "reasoning": reasoning, 
            "solution": solution
        }
        
        if SAVE_DEBUG: save_json(LOKI_INPUT_DIR, f"loki_{alert['label']}", event_json)
        if ENABLE_LOKI: push_to_loki(event_json)

    except Exception as e:
        logging.error(f"Error in IO Thread: {e}")

# =================== ANALYSIS LOGIC ===================
def analyze_window_optimized(flows, duration_seconds=1.0):
    if not flows: return []
    
    df = pd.DataFrame(flows)
    
    # 1. Soft Voting Filter
    valid_flows_mask = df['confidence'] >= FILTER_CONFIDENCE_THRESHOLD
    valid_df = df[valid_flows_mask].copy()
    
    if valid_df.empty: return []

    # 2. Check Benign Ratio
    is_benign = valid_df['primary_label'].str.lower().str.contains('benign', na=False)
    benign_count = is_benign.sum()
    total_valid_count = len(valid_df)
    
    benign_ratio = benign_count / total_valid_count if total_valid_count > 0 else 0
    
    # 3. Decision Logic
    target_df = None
    
    if benign_ratio >= BENIGN_RATIO_THRESHOLD:
        target_df = valid_df[is_benign].copy()
        logging.info(f"[DEBUG] Window SAFE. Benign Ratio: {benign_ratio:.2%} >= {BENIGN_RATIO_THRESHOLD}. Showing BenignTraffic.")
    else:
        target_df = valid_df[~is_benign].copy()
        logging.info(f"[DEBUG] Window ATTACK. Benign Ratio: {benign_ratio:.2%} < {BENIGN_RATIO_THRESHOLD}. Showing Attacks.")

    if target_df.empty: return []

    # 4. Aggregation
    grouped = target_df.groupby(['dst_ip', 'dst_port', 'protocol', 'primary_label'])
    alerts = []
    
    for (dst_ip, dst_port, protocol, label), grp in grouped:
        count = len(grp)
        flow_rate = count / max(duration_seconds, 1.0)
        unique_src_count = len(grp['src_ip'].unique())
        avg_conf = float(grp['confidence'].mean())
        window_end = int(grp['timestamp'].max())

        if "benign" in str(label).lower():
            attack_type = "N/A"
        elif unique_src_count >= DDOS_MIN_UNIQUE_IPS:
            attack_type = "DDoS"
        else:
            attack_type = "DoS"
            
        alerts.append({
            "label": label,
            "subtype": attack_type,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),       
            "protocol": str(protocol),       
            "flows_count": int(count),       
            "flow_rate_per_sec": round(float(flow_rate), 2), 
            "avg_conf": round(avg_conf, 3),
            "unique_src_count": int(unique_src_count),
            "src_ip_list": grp['src_ip'].unique().tolist()[:50], 
            "window_end": window_end
        })
            
    alerts.sort(key=lambda x: x["flows_count"], reverse=True)
    return alerts

def process_window_data_logic(flows, duration_seconds=10.0):
    global benign_last_ts
    start_cpu = time.time()
    
    alerts = analyze_window_optimized(flows, duration_seconds)
    
    cpu_time = time.time() - start_cpu
    if cpu_time > 1.0: logging.warning(f"CPU Logic took {cpu_time:.2f}s")

    if not alerts: return
    
    for alert in alerts:
        if alert['subtype'] == "N/A":
            now = time.time()
            if now - benign_last_ts >= BENIGN_INTERVAL:
                logging.info(f"--> Pushing [BenignTraffic] to Dashboard (Conf: {alert['avg_conf']})")
                benign_last_ts = now
                io_executor.submit(handle_alert_io_task, alert)
            else:
                pass 
        else:
            logging.warning(
                f"!!! ALERT [{alert['subtype']}]: {alert['label']} "
                f"-> {alert['dst_ip']}:{alert['dst_port']} | Conf: {alert['avg_conf']}"
            )
            io_executor.submit(handle_alert_io_task, alert)