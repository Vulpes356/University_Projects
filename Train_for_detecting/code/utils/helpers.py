import re
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

PROTOCOL_MAP = {
    6: "TCP", 17: "UDP", 1: "ICMP"
}

def canonical_no_space(s: str) -> str:
    return re.sub(r"[^0-9a-z]+", "", s.lower()) if s else ""

def get_value_from_aliases(data: dict, aliases: list, default=None):
    data_lower = {k.lower(): v for k, v in data.items()}
    for alias in aliases:
        if alias.lower() in data_lower:
            return data_lower[alias.lower()]
    return default

def apply_temperature_scaling(probs, temperature=1.0):
    probs = np.clip(probs, 1e-9, 1.0)
    logits = np.log(probs) / temperature
    exp_logits = np.exp(logits)
    return exp_logits / np.sum(exp_logits)

def get_binary_metrics_per_class(y_true, y_pred, mapping):
    classes_ids = sorted(mapping.values())
    inv_map = {v: k for k, v in mapping.items()}
    metrics_list = []
    
    cm = confusion_matrix(y_true, y_pred, labels=classes_ids)
    
    for i, class_id in enumerate(classes_ids):
        label_name = inv_map[class_id]
        TP = cm[i, i]
        FP = cm[:, i].sum() - TP
        FN = cm[i, :].sum() - TP
        TN = cm.sum() - (TP + FP + FN)
        
        eps = 1e-7
        Accuracy = (TP + TN) / (TP + TN + FP + FN + eps)
        Precision = TP / (TP + FP + eps)
        Recall = TP / (TP + FN + eps)
        Specificity = TN / (TN + FP + eps)
        F1 = 2 * (Precision * Recall) / (Precision + Recall + eps)
        
        metrics_list.append({
            "Label_ID": class_id, "Label_Name": label_name,
            "TP": TP, "TN": TN, "FP": FP, "FN": FN,
            "Accuracy": round(Accuracy, 4), "Precision": round(Precision, 4),
            "Recall": round(Recall, 4), "Specificity": round(Specificity, 4),
            "F1_Score": round(F1, 4)
        })
        
    return pd.DataFrame(metrics_list)