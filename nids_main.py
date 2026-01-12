import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# PAGE CONFIGURATION
st.set_page_config(page_title="Cyber Threat Dashboard", layout="wide")

# Custom Title and Description
st.title("Real-Time Cyber Threat Intelligence & Traffic Visualization Dashboard")
st.markdown("""
### Project Overview
This system uses Machine Learning (**Random Forest**) to detect cyberattacks in real-time.
It visualizes network traffic data and classifies it as either **Safe (Benign)** or **Malicious (Attack)**.
""")

# --- 1. DATA LOADING (Real Data Logic) ---
@st.cache_data
def load_data():
    # filename must match your downloaded file exactly
    filename = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
    
    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        st.error(f"Error: File '{filename}' not found. Please download it and put it in the folder!")
        return pd.DataFrame()

    # Clean data: Remove spaces from column names
    df.columns = df.columns.str.strip()
    
    # Select specific columns for the model
    required_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Packet Length Mean', 'Active Mean', 'Label']
    
    # Check if columns exist
    if not all(col in df.columns for col in required_cols):
        st.error(f"Missing columns! Your file has: {list(df.columns)}")
        return pd.DataFrame()

    df = df[required_cols]
    
    # Rename columns to match code variables
    df.columns = ['Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Packet_Length_Mean', 'Active_Mean', 'Label']
    
    # Convert Labels (BENIGN=0, Attack=1)
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    
    # Drop empty rows
    df = df.dropna()
    return df

# Load the data
df = load_data()

# Show success message if loaded
if not df.empty:
    st.success(f"Real Data Successfully Loaded: {len(df)} rows found.")
else:
    st.warning("Data not loaded. Please check the CSV file.")

# --- SIDEBAR CONTROLS ---
st.sidebar.header("Control Panel")
st.sidebar.info("Adjust model settings here.")
split_size = st.sidebar.slider("Training Data Size (%)", 50, 90, 80)
n_estimators = st.sidebar.slider("Number of Trees", 10, 500, 100)

# --- 2. PREPROCESSING ---
if not df.empty:
    X = df.drop('Label', axis=1)
    y = df['Label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=(100-split_size)/100, random_state=42)

    # --- 3. TRAINING SECTION ---
    st.divider()
    col_train, col_metrics = st.columns([1, 2])

    with col_train:
        st.subheader("1. Model Training")
        if st.button("Train Model Now"):
            with st.spinner("Training Random Forest Classifier..."):
                model = RandomForestClassifier(n_estimators=n_estimators)
                model.fit(X_train, y_train)
                st.session_state['model'] = model
                st.success("Training Complete!")
        
        if 'model' in st.session_state:
            st.success("Model is Ready for Testing")

    # --- 4. METRICS & VISUALIZATION ---
    with col_metrics:
        st.subheader("2. Performance Metrics")
        if 'model' in st.session_state:
            model = st.session_state['model']
            y_pred = model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            
            # Display Metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Accuracy", f"{acc*100:.2f}%")
            m2.metric("Total Samples", len(df))
            m3.metric("Detected Threats", np.sum(y_pred))
            
            # Confusion Matrix
            st.write("### Confusion Matrix")
            cm = confusion_matrix(y_test, y_pred)
            fig, ax = plt.subplots(figsize=(4, 2))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax)
            st.pyplot(fig)

            # --- NEW FEATURE 1: PIE CHART ---
            st.write("### 3. Data Distribution (Safe vs Attack)")
            counts = df['Label'].value_counts()
            labels = ['Safe (0)', 'Attack (1)']
            fig2, ax2 = plt.subplots(figsize=(4, 3))
            ax2.pie(counts, labels=labels, autopct='%1.1f%%', colors=['#66b3ff', '#ff9999'], startangle=90)
            st.pyplot(fig2)

            # --- NEW FEATURE 2: FEATURE IMPORTANCE ---
            st.write("### 4. Feature Importance (How AI Thinks)")
            importance = model.feature_importances_
            feature_names = X.columns
            feature_df = pd.DataFrame({'Feature': feature_names, 'Importance': importance})
            feature_df = feature_df.sort_values(by='Importance', ascending=False)
            
            fig3, ax3 = plt.subplots(figsize=(6, 3))
            sns.barplot(x='Importance', y='Feature', data=feature_df, palette='viridis', ax=ax3)
            st.pyplot(fig3)

        else:
            st.warning("Please train the model first to see charts.")

    # --- 5. LIVE SIMULATOR (UNLOCKED TO 2 BILLION) ---
    st.divider()
    st.subheader("3. Live Traffic Simulator")
    st.write("Enter network packet details to test the AI.")
    
    # We use min_value=0 and max_value=2000000000 (2 Billion) to allow huge inputs
    c1, c2, c3, c4 = st.columns(4)
    p_dur = c1.number_input("Flow Duration", min_value=0, max_value=2000000000, value=500)
    p_pkts = c2.number_input("Total Packets", min_value=0, max_value=2000000000, value=100)
    p_len = c3.number_input("Packet Length Mean", min_value=0, max_value=2000000000, value=500)
    p_active = c4.number_input("Active Mean", min_value=0, max_value=2000000000, value=50)

    if st.button("Analyze Packet"):
        if 'model' in st.session_state:
            model = st.session_state['model']
            # Port is set to random 80 for input simplicity
            input_data = np.array([[80, p_dur, p_pkts, p_len, p_active]])
            pred = model.predict(input_data)
            
            if pred[0] == 1:
                st.error("ALERT: MALICIOUS TRAFFIC DETECTED!")
                st.write("**Analysis:** The model flagged this pattern as an attack signature.")
            else:
                st.success("Traffic Status: BENIGN (Safe)")
        else:
            st.error("Train the model first!")

    # --- 6. CHEAT SHEET (Always Visible) ---
    st.divider()
    st.subheader("4. Cheat Sheet (Real Attack Data)")
    st.write("Copy the values from the first row below to trigger a RED alert:")
    if not df.empty:
        # Show top 5 rows where Label is 1 (Attack)
        st.dataframe(df[df['Label'] == 1].head(5))