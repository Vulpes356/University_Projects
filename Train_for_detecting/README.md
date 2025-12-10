# ML Module - Machine Learning Detection System

## Module Description

ML module is responsible for detecting DOS/DDOS attacks in IoT MQTT environment using LightGBM model.

## Responsible member

- **Dien**: Presentation, answer questions about ML module
- **Phuoc**: Implementation, model maintenance, responsibility

## Introduction
The Machine Learning (ML) module serves as the core detection engine for identifying Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks within IoT environments using the MQTT protocol. The system utilizes a highly optimized LightGBM model for real-time traffic classification and integrates with a Large Language Model (LLM) to provide natural language explanations and mitigation strategies for detected threats.

## Directory Structure

The project follows a standard MLOps structure. Training is performed via Jupyter Notebooks, while inference logic is modularized for production deployment.

```text
ml/
├── code/                         # Source code
│   ├── training/                 # Model training
│   │   ├── train_pipeline.ipynb  # Main Training Notebook (Feature Selection, Training, Eval)
│   │   └── __init__.py
│   ├── inference/                # Real-time detection system
│   │   ├── api_server.py         # FastAPI Listener
│   │   ├── core_logic.py         # Main business logic (Windowing, Rules, LLM)
│   │   ├── packet_sniffer.py     # Network traffic capture tool
│   │   └── __init__.py
│   └── utils/                    # Shared utility functions
│       ├── helpers.py            # Data processing, math, metrics
│       ├── paths.py              # Absolute path management
│       └── __init__.py
├── models/                       # Training artifacts
│   ├── LightGBM_model.pkl        # Trained model object
│   ├── scaler.pkl                # StandardScaler object
│   ├── label_mapping.pkl         # Label encoder mapping
│   └── selected_features.txt     # List of features used for training
├── documentation/                # Logs and Reports
│   ├── reports/                  # Confusion Matrix, Feature Importance plots
│   └── alerts/                   # JSON logs of generated alerts
└── README.md                     # Project documentation
```

## Model Information
The system deploys LightGBM for production due to its superior inference speed and handling of numerical flow-based features.

- **Algorithm**: LightGBM (LGBMClassifier)
- **Configuration**:
  - **Objective**: Multiclass
  - **Class Weight**: Balanced (Handles imbalanced datasets effectively)
  - **Regularization**: L1 (reg_alpha=5.0), L2 (reg_lambda=10.0) to prevent overfitting
- **Input Features**: Flow-based statistics including Flow Duration, Inter-arrival Time (IAT), TCP Flag Counts, Packet Size (Min, Max, Avg, Total).

## Detected Attack Types
The model is trained to detect over 15 types of attacks, categorized into two groups:

1. **General Network Attacks**
    - **Flood Attacks**: SYN_Flood, UDP_Flood, ICMP_Flood, TCP_ACK_Flood, PSHACK_Flood, RSTFINFlood.
    - **Fragmentation**: UDP_Fragmentation, ICMP_Fragmentation, ACK_Fragmentation.
    - **Evasion**: SynonymousIP_Flood.

2. **MQTT Application Attacks**
    - **CONNECT Flooding**: Exhausting broker resources with connection requests.
    - **Delayed CONNECT**: Holding connections open to consume sockets.
    - **Subscription Flooding**: Overloading the broker with topic subscriptions.
    - **WILL Payload Attack**: Exploiting MQTT Last Will and Testament features.

## Key Features
### Multi-Vector Alerting
The system can detect and report multiple simultaneous attack vectors. Instead of reporting only the dominant attack, it generates a list of alerts for all attack types exceeding the confidence threshold within a time window.

### Smart IP Lookup
The inference engine parses incoming JSON payloads to extract Source/Destination IPs and Ports, supporting various key formats (e.g., `src_ip`, `Source IP`, `id.orig_h`) to ensure compatibility with different traffic capture tools.

### Confidence Calibration
Raw model probabilities are processed using *Temperature Scaling* to produce calibrated confidence scores (rounded to 3 decimal places). This prevents over-confidence in incorrect predictions.

### Advanced Logic Rules
- **Benign Threshold**: If `>= 90%` of traffic in a time window is normal, the system classifies the window as Benign to reduce false positives.
- **DDoS and DoS Logic**:
  - 5 Unique Source IPs: Classified as DDoS.
  - 1-5 Unique Source IPs: Classified as DoS.

### LLM Integration
The system integrates with `Qwen-2.5-0.5B` (via local API) to analyze attack metadata and generate human-readable reasoning and solution steps.

### Observability
- **Grafana Loki**: Logs are pushed to *Loki* for centralized dashboard monitoring.
- **Local Logging**: Detailed logs are organized in `documentation/alerts` and `documentation/loki_inputs`.

## Usage Guide
  1. **Training Model**: 
  Training is performed using the provided Jupyter Notebook.
      1. Open `ml/code/training/train_pipeline.ipynb`.
      2. Ensure the path setup cell is executed.
      3. Run the notebook to perform Feature Selection, Training, and Evaluation.
  Artifacts will be saved to `ml/models/` and reports to `ml/documentation/reports/`.

  2. **Start Inference Server**: 
  The server consists of the API listener and the core logic engine. The server listens on port `8000` by default.
  ```
  python ml/code/inference/api_server.py
  ```

## System Workflow
1. **Ingestion**: API Server receives flow data via HTTP POST.
2. **Preprocessing**: Data is parsed (Smart IP Lookup) and buffered.
3. **Inference**:
    - Data is scaled using the pre-loaded Scaler.
    - LightGBM model predicts the label.
    - Confidence score is calibrated.
4. **Window Analysis**:
    - Rules are applied (90% Benign threshold).
    - Attacks are grouped by type.
    - Multi-vector analysis determines distinct alerts.
5. **Alerting**:
    - Alerts are sent to LLM for reasoning.
    - Data is formatted and pushed to Grafana Loki.
    - Local logs are updated in the documentation folder.

