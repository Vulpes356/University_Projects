import os
import re
import json
import time
import pickle
import asyncio
import logging
from pathlib import Path
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from fastapi import FastAPI, Request
from sklearn.preprocessing import StandardScaler
import requests

# =================== CONFIG ===================
MODEL_DIR = os.environ.get("MODEL_DIR", "./models")
MODEL_FILE = "LightGBM_model.pkl"
SCALER_FILE = "scaler.pkl"
LABEL_MAP_FILE = "label_mapping.pkl"
FEATURE_FILE = "selected_features.txt"

ALERT_DIR = "./alerts"
DEBUG_DIR = "./debug_payloads"
LOKI_INPUT_DIR = "./loki_inputs"
for d in [ALERT_DIR, DEBUG_DIR, LOKI_INPUT_DIR]:
    Path(d).mkdir(exist_ok=True, parents=True)

WINDOW_INTERVAL = 10
SAVE_DEBUG = True

ENABLE_LLM = True
ENABLE_LOKI = True

BENIGN_INTERVAL = 60
benign_last_ts = 0.0

# Read external service endpoints and keys from environment to avoid hardcoding secrets
VLLM_URL = os.environ.get("VLLM_URL", "http://localhost:9090/v1/chat/completions")
VLLM_API_KEY = os.environ.get("VLLM_API_KEY", "")
LOKI_PUSH = os.environ.get("LOKI_PUSH", "http://localhost:1515/loki/api/v1/push")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# =================== LOAD MODEL ===================
logging.info("Loading model, scaler, features, and label mapping...")
with open(os.path.join(MODEL_DIR, "models", MODEL_FILE), "rb") as f:
    model_obj = pickle.load(f)

# handle model object formats (dict with 'model' key or raw model)
model = model_obj["model"] if isinstance(model_obj, dict) and "model" in model_obj else model_obj
features = model_obj.get("features", []) if isinstance(model_obj, dict) else []

with open(os.path.join(MODEL_DIR, "models", SCALER_FILE), "rb") as f:
    scaler: StandardScaler = pickle.load(f)
    
with open(os.path.join(MODEL_DIR, LABEL_MAP_FILE), "rb") as f:
    label_mapping = pickle.load(f)
id_to_label = {v: k for k, v in label_mapping.items()}

if not features:
    try:
        with open(os.path.join(MODEL_DIR, FEATURE_FILE), "r") as f:
            features = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.warning("Feature file not found, relying on model features if available.")

logging.info(f"[+] Model loaded ({len(features)} features)")

# =================== FASTAPI ===================
app = FastAPI(title="ML Server v7 (Fixed DDoS Logic)")
flow_buffer = []

# =================== HELPERS ===================
def canonical_no_space(s: str) -> str:
    return re.sub(r"[^0-9a-z]+", "", s.lower()) if s else ""

feature_alias = {canonical_no_space(f): f for f in features}

def save_json(folder: str, prefix: str, data: dict):
    ts = int(time.time())
    fname = os.path.join(folder, f"{prefix}_{ts}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return fname

def save_text(folder: str, prefix: str, content: str):
    ts = int(time.time())
    fname = os.path.join(folder, f"{prefix}_{ts}.txt")
    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)
    return fname

def apply_temperature_scaling(probs, temperature=1.0):
    """Apply temperature scaling to a probability vector."""
    probs = np.clip(probs, 1e-9, 1.0)
    logits = np.log(probs)
    logits = logits / temperature
    exp_logits = np.exp(logits)
    scaled_probs = exp_logits / np.sum(exp_logits)
    return scaled_probs

# =================== LLM ===================
system_prompt = (
    "You are a network security analyst. When given attack data, explain what's happening and how to fix it."
    "Use specific numbers and details from the data provided. Keep explanations simple and practical."
    "Always respond with only a JSON object: {'reasoning': '...', 'solution': '...'}."
)

def build_llm_payload(wa):
    user_lines = [f"{k}={json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else v}" for k, v in wa.items()]
    return {
        "model": "Qwen/Qwen2.5-0.5B-Instruct",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "\n".join(user_lines)}
        ],
        "temperature": 0.3,
        "max_tokens": 800,
        "top_p": 0.8
    }

def call_vllm(payload):
    # Build headers; include Authorization only if API key provided
    headers = {"Content-Type": "application/json"}
    if VLLM_API_KEY:
        headers["Authorization"] = f"Bearer {VLLM_API_KEY}"
    try:
        r = requests.post(VLLM_URL, headers=headers, json=payload, timeout=30)
        if r.status_code != 200:
            logging.error(f"vLLM returned {r.status_code}: {r.text[:200]}")
            return None
        return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logging.error(f"vLLM Connection Error: {e}")
        return None

def parse_llm_output(text):
    """Parse LLM output (expected JSON)."""
    if not isinstance(text, str):
        return {"reasoning": "LLM Error or Empty", "solution": "Check system manually"}
    raw = text.strip()
    logging.info(f"[LLM RAW OUTPUT] {raw}")
    try:
        if not raw.startswith("{"):
            m = re.search(r"\{.*\}", raw, flags=re.DOTALL)
            if m:
                raw = m.group(0)
        obj = json.loads(raw)
    except Exception:
        save_text(DEBUG_DIR, "llm_bad_output", text)
        return {"reasoning": raw[:200], "solution": "Parsing failed, check raw output"}

    if isinstance(obj, dict):
        keys = {k.lower(): v for k, v in obj.items()}
        return {"reasoning": keys.get("reasoning", "N/A"), "solution": keys.get("solution", "N/A")}    
    return {"reasoning": "Invalid format", "solution": "N/A"}

# =================== LOKI ===================
def push_to_loki(event_json):
    payload = {
        "streams": [
            {
                "stream": {"job": "llm_gateway"},
                "values": [[str(int(time.time() * 1e9)), json.dumps(event_json, ensure_ascii=False)]]
            }
        ]
    }
    for attempt in range(2):
        try:
            r = requests.post(LOKI_PUSH, json=payload, timeout=5)
            if r.status_code in (200, 204):
                return True
            logging.warning(f"Loki push failed ({r.status_code}), retrying...")
        except Exception as e:
            logging.warning(f"Loki error: {e}, retrying...")
            time.sleep(1)
    logging.error("Failed to push to Loki after retries")
    return False

# =================== INGEST ===================
@app.post("/ingest_flow")
async def ingest_flow(request: Request):
    payload = await request.json()
    if isinstance(payload, dict) and "flows" in payload:
        payload = payload["flows"][0]

    remapped = {}
    for k, v in payload.items():
        key = canonical_no_space(k)
        if key in feature_alias:
            remapped[feature_alias[key]] = v

    # build DataFrame with expected feature order
    df = pd.DataFrame([remapped]).reindex(columns=features, fill_value=0)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

    # scale features
    X_scaled = pd.DataFrame(scaler.transform(df[features].astype(np.float32)), columns=features)

    try:
        # 1. raw probabilities
        raw_probs = model.predict_proba(X_scaled)[0]

        # 2. apply temperature scaling to reduce over-confidence
        scaled_probs = apply_temperature_scaling(raw_probs, temperature=1.5)

        # 3. choose label from scaled probabilities
        max_idx = np.argmax(scaled_probs)
        if hasattr(model, "classes_"):
            predicted_class_id = model.classes_[max_idx]
        else:
            predicted_class_id = max_idx
        label = id_to_label.get(int(predicted_class_id), "Unknown")
        conf = float(scaled_probs[max_idx])

    except Exception as e:
        logging.exception("Predict error")
        return {"status": "error", "message": str(e)}

    src = payload.get("src_ip", "0.0.0.0")
    dst = payload.get("dst_ip", "0.0.0.0")
    port = payload.get("dst_port", 1883)

    flow_buffer.append({
        "timestamp": int(time.time()),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "primary_label": label,
        "confidence": conf
    })

    return {"status": "ok", "label": label, "confidence": conf}

# =================== WINDOW ANALYSIS (FIXED LOGIC) ===================
def analyze_window(flows):
    """Aggregate flows in a window and select highest-priority alert."""
    if len(flows) < 1:
        return None

    total = len(flows)
    # group by (label, dst_ip, dst_port)
    groups = defaultdict(list)
    for f in flows:
        groups[(f["primary_label"], f["dst_ip"], f["dst_port"])].append(f)

    best_alert = None
    for (label, dst_ip, dst_port), grp in groups.items():
        srcs = [g["src_ip"] for g in grp]
        confs = [g["confidence"] for g in grp]

        unique_src_count = len(set(srcs))
        if "benign" in label.lower():
            subtype = "N/A"
        elif unique_src_count > 2:
            subtype = "DDoS"
        else:
            subtype = "DoS"

        pct = (len(grp) / total) * 100
        current_alert = {
            "label": label,
            "dst": f"{dst_ip}:{dst_port}",
            "flows": len(grp),
            "avg_conf": np.mean(confs),
            "percent": pct,
            "subtype": subtype,
            "top_srcs": Counter(srcs).most_common(3),
            "window_end": max(f["timestamp"] for f in grp)
        }

        # choose alert: prefer attack over benign, then higher percent
        if best_alert is None:
            best_alert = current_alert
        else:
            if "benign" not in current_alert["label"].lower() and "benign" in best_alert["label"].lower():
                best_alert = current_alert
            elif ("benign" in current_alert["label"].lower()) == ("benign" in best_alert["label"].lower()):
                if current_alert["percent"] > best_alert["percent"]:
                    best_alert = current_alert

    return best_alert

def llm_payload_handler(llm_input):
    """Call LLM payload with simple validation and retries."""
    BANNED_PHRASES = [
        "to fix this", "the following steps", "here are the steps",
        "mitigation steps", "steps to taken", "can be taken"
    ]
    LIST_INDICATORS = ["\n", "\\n", "1.", "2.", "- ", "* "]
    retries = 3

    for i in range(retries):
        try:
            payload = build_llm_payload(llm_input)
            raw = call_vllm(payload)
            if raw:
                parsed = parse_llm_output(raw)
                reasoning = parsed.get("reasoning", "").strip()
                solution = parsed.get("solution", "").strip()

                sol_lower = solution.lower()
                has_banned_phrase = any(phrase in sol_lower[:30] for phrase in BANNED_PHRASES)
                is_list_format = any(indicator in solution for indicator in LIST_INDICATORS)
                is_too_short = len(solution) < 10

                if has_banned_phrase or is_list_format or is_too_short:
                    logging.warning(f"[LLM] Retry {i+1}/{retries}: Output format invalid.")
                    if i < retries - 1:
                        time.sleep(0.5)
                        continue
                return reasoning, solution
        except Exception as e:
            logging.warning(f"LLM Error (attempt {i+1}): {e}")
            time.sleep(1)

    if 'solution' in locals() and isinstance(solution, str):
        clean_sol = solution.replace("\n", ". ").replace("..", ".")
        return reasoning, clean_sol
    return "LLM unavailable", "Check logs"

async def wa_loop():
    global benign_last_ts

    while True:
        await asyncio.sleep(WINDOW_INTERVAL)
        if not flow_buffer:
            continue

        flows = flow_buffer.copy()
        flow_buffer.clear()

        alert = analyze_window(flows)
        if not alert:
            continue

        # throttle benign alerts
        if "benign" in alert["label"].lower():
            now_ts = time.time()
            if now_ts - benign_last_ts < BENIGN_INTERVAL:
                continue
            benign_last_ts = now_ts

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert["window_end"]))
        src_top = alert["top_srcs"][0][0] if alert["top_srcs"] else "0.0.0.0"
        dst_ip, dst_port = alert["dst"].split(":")

        reasoning, solution = "(no LLM)", "(no LLM)"
        if ENABLE_LLM:
            llm_input = {
                "wid": f"win-{timestamp}",
                "primary_label": alert["label"],
                "src_ip": src_top,
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "_meta": {"avg_conf": round(alert["avg_conf"], 3), "count": alert["flows"]}
            }
            if SAVE_DEBUG:
                save_json(ALERT_DIR, "llm_input_window", llm_input)
            reasoning, solution = llm_payload_handler(llm_input)

        total_flows = len(flows)
        src_counts = Counter(f["src_ip"] for f in flows)
        dst_counts = Counter(f["dst_ip"] for f in flows)

        hot_src_ips = [ip for ip, c in src_counts.items() if (c / total_flows) >= 0.5]
        hot_dst_ips = [ip for ip, c in dst_counts.items() if (c / total_flows) >= 0.3]
        if not hot_src_ips and alert["top_srcs"]:
            hot_src_ips = [alert["top_srcs"][0][0]]
        if not hot_dst_ips:
            hot_dst_ips = [dst_ip]

        clean_subtype = re.sub(r'(?i)\b(ddos|dos)_?', '', alert["label"]).strip("_")
        if not clean_subtype:
            clean_subtype = "Generic"

        event_json = {
            "timestamp": timestamp,
            "src_ip": src_top,
            "dst_ip": dst_ip,
            "protocol": "UDP",
            "dst_port": int(dst_port),
            "attack_type": alert["subtype"],
            "attack_subtype": clean_subtype,
            "confidence": round(alert["avg_conf"], 10),
            "reasoning": reasoning,
            "solution": solution,
            "hot_src_ips": hot_src_ips,
            "hot_dst_ips": hot_dst_ips
        }

        if SAVE_DEBUG:
            save_json(LOKI_INPUT_DIR, "loki_input", event_json)

        logging.info(f"[ALERT] {alert['label']} | Type: {alert['subtype']} | Conf: {alert['avg_conf']:.2f}")
        if ENABLE_LOKI:
            push_to_loki(event_json)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(wa_loop())
    logging.info("[+] ML Server is ready.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)