Here's a professional README file for the Python script that detects anomalous behavior in logs, suitable for a GitHub repository.

---

# Anomalous Behavior Detection in Logs

This repository contains a Python script for detecting anomalous behavior in logs using machine learning, specifically an Isolation Forest model. The script is designed for blue team operations, allowing security teams to identify potential threats or irregularities in system logs.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Log Format](#log-format)
  - [Running the Script](#running-the-script)
- [Configuration](#configuration)
- [Model Training](#model-training)
- [Anomaly Detection](#anomaly-detection)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Log Ingestion**: Automatically loads and processes log files from a specified directory.
- **Anomaly Detection**: Uses an Isolation Forest model to detect anomalous entries in the logs.
- **Customizable Parsing**: Easily adaptable to different log formats via regex parsing.
- **Model Persistence**: Trained models and scalers can be saved and reused.

## Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourusername/anomalous-log-detection.git
cd anomalous-log-detection
pip install -r requirements.txt
```

### Dependencies

- `pandas`
- `scikit-learn`
- `joblib`

You can install these dependencies using the provided `requirements.txt` file.

## Usage

### Log Format

The script expects logs in plain text format. Each log entry should follow a consistent structure that can be parsed using regular expressions. For example, the log format might include a timestamp, IP address, event type, and additional details:

```
2024-08-28 12:45:23 192.168.0.1 LOGIN_SUCCESS User JohnDoe logged in
```

### Running the Script

1. **Place Your Logs**: Place your log files in a directory (e.g., `./logs`).
2. **Run the Script**: Execute the script to process the logs and detect anomalies.

```bash
python sherlock.py
```

### Output

The script will output the number of detected anomalous entries and print the details of these anomalies to the console.

## Configuration

You can configure the script by modifying the following variables in the script:

- `LOGS_FOLDER`: Path to the directory containing the log files.
- `MODEL_SAVE_PATH`: Path where the trained model and scaler will be saved.

## Model Training

The script automatically trains an Isolation Forest model on the ingested log data. The model is then saved for future use, allowing for consistent anomaly detection across different runs.

## Anomaly Detection

The script uses the trained Isolation Forest model to classify log entries as either normal or anomalous. Anomalies are marked in the output DataFrame with an `Anomaly` column, where `-1` indicates an anomaly.

## Contributing

Contributions are welcome! If you have ideas for improvements or find bugs, feel free to submit an issue or create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
