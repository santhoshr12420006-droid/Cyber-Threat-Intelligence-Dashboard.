# Real-Time Cyber Threat Intelligence & Traffic Visualization Dashboard

## 📌 Project Overview
This project is an advanced **AI-Powered Network Intrusion Detection System (NIDS)** designed to detect cyberattacks (such as DDoS) in real-time. Unlike traditional firewalls, it uses **Machine Learning (Random Forest)** to analyze network traffic behavior and visualize threat data instantly.

## 🚀 Key Features
* **Real-Time Detection:** Instantly classifies network traffic as "Benign" (Safe) or "Malicious" (Attack).
* **Traffic Visualization:** Includes dynamic Pie Charts and Graphs to analyze attack distribution.
* **Explainable AI (XAI):** Uses Feature Importance to explain *why* a specific packet was flagged (e.g., High Flow Duration).
* **Live Simulator:** Built-in tool to simulate hacker attacks and test the system's response.

## 🛠️ Technologies Used
* **Language:** Python 3.9+
* **Machine Learning:** Scikit-Learn (Random Forest Classifier)
* **Web Framework:** Streamlit
* **Data Processing:** Pandas, NumPy
* **Visualization:** Matplotlib, Seaborn

## 📂 Dataset
The model is trained on the **CIC-IDS2017** dataset, a benchmark dataset for real-world cyberattacks, ensuring high accuracy in detecting modern threats.

## ⚡ How to Run
1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the application:
    ```bash
    streamlit run nids_main.py
    ```
