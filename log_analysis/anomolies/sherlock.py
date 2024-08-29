import os
import re
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Configure the path to the logs folder and model save path
LOGS_FOLDER = './logs'
MODEL_SAVE_PATH = './model/isolation_forest.pkl'

def load_logs(logs_folder):
    """
    Load all text log files from a specified folder and extract relevant features.
    
    :param logs_folder: Path to the folder containing log files.
    :return: DataFrame containing extracted log features.
    """
    all_logs = []
    for file_name in os.listdir(logs_folder):
        if file_name.endswith('.txt'):
            file_path = os.path.join(logs_folder, file_name)
            with open(file_path, 'r') as file:
                log_entries = file.readlines()
                for entry in log_entries:
                    parsed_entry = parse_log_entry(entry)
                    if parsed_entry:
                        all_logs.append(parsed_entry)
    
    if not all_logs:
        raise ValueError("No valid log entries found in the specified folder.")
    
    log_df = pd.DataFrame(all_logs)
    return log_df

def parse_log_entry(log_entry):
    """
    Parse a single log entry to extract relevant features.
    
    :param log_entry: A single log entry as a string.
    :return: A dictionary with extracted features, or None if parsing fails.
    """
    # Example: Extracting timestamp, IP address, and event type from a log entry
    # Customize this regular expression based on your log format
    log_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+' \
                  r'(?P<ip_address>\d+\.\d+\.\d+\.\d+)\s+' \
                  r'(?P<event_type>\w+)\s+' \
                  r'(?P<details>.+)'
    
    match = re.match(log_pattern, log_entry)
    if match:
        return match.groupdict()
    else:
        return None

def preprocess_logs(log_df):
    """
    Preprocess logs by encoding categorical features and scaling numerical features.
    
    :param log_df: DataFrame containing logs.
    :return: Scaled log features.
    """
    # Convert categorical features to numerical using one-hot encoding
    log_df = pd.get_dummies(log_df, columns=['event_type'])
    
    # Handle missing data (e.g., replace missing values with zero or mean)
    log_df.fillna(0, inplace=True)
    
    # Convert IP address to a numerical format (e.g., using integer representation)
    log_df['ip_address'] = log_df['ip_address'].apply(ip_to_int)
    
    # Select numerical features for scaling
    numerical_features = log_df.select_dtypes(include=['float64', 'int64']).columns
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(log_df[numerical_features])
    
    return scaled_features, numerical_features, scaler

def ip_to_int(ip_address):
    """
    Convert an IP address to a numerical integer format.
    
    :param ip_address: IP address as a string.
    :return: Integer representation of the IP address.
    """
    octets = ip_address.split('.')
    return sum(int(octet) << (8 * (3 - idx)) for idx, octet in enumerate(octets))

def train_model(features):
    """
    Train an Isolation Forest model to detect anomalies.
    
    :param features: Preprocessed log features.
    :return: Trained model.
    """
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(features)
    
    return model

def save_model(model, scaler, save_path):
    """
    Save the trained model and scaler to a file.
    
    :param model: Trained Isolation Forest model.
    :param scaler: Scaler used for preprocessing.
    :param save_path: Path where the model will be saved.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump({'model': model, 'scaler': scaler}, save_path)
    print(f"Model and scaler saved to {save_path}")

def detect_anomalies(model, features):
    """
    Use the trained model to detect anomalies in the log data.
    
    :param model: Trained Isolation Forest model.
    :param features: Preprocessed log features.
    :return: DataFrame indicating which records are anomalies.
    """
    predictions = model.predict(features)
    return predictions

def main():
    # Load and preprocess logs
    log_df = load_logs(LOGS_FOLDER)
    features, numerical_features, scaler = preprocess_logs(log_df)
    
    # Train model
    model = train_model(features)
    
    # Save model
    save_model(model, scaler, MODEL_SAVE_PATH)
    
    # Detect anomalies
    anomalies = detect_anomalies(model, features)
    log_df['Anomaly'] = anomalies
    
    # Print or save the logs with anomalies marked
    anomalous_logs = log_df[log_df['Anomaly'] == -1]
    print(f"Detected {len(anomalous_logs)} anomalous entries.")
    print(anomalous_logs)

if __name__ == "__main__":
    main()

