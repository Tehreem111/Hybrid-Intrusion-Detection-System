# Hybrid Intrusion Detection System 

A cross-layer hybrid intrusion detection framework integrating transport-layer network attributes (NSL-KDD dataset) with live host Windows Registry telemetry to eliminate detection blind spots.

## 🌟 Key Features
- **Cross-Layer Fusion:** Combines network traffic flow with host endpoint telemetry.
- **Random Forest Engine:** Achieves high accuracy on benchmark network data.
- **Protocol Behavior Score (PBS):** Low-latency pre-filtering engine (65ms).
- **Interactive Dashboard:** Built with Streamlit for real-time visual threat telemetry.

## 📊 Performance Graphs
The trained model evaluation graphs are available in the `images/` directory:
- Protocol Risk Analysis
- Accuracy Comparison
- Latency Analysis

## 🚀 How to Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt