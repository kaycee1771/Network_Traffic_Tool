import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Function to prepare data for machine learning
def prepare_data(input_csv="reports/parsed_packets.csv", output_csv="reports/processed_data.csv"):
    """
    This function prepares the data for machine learning by encoding categorical variables 
    and creating labels for classification.
    
    Args:
        input_csv (str): Path to the input parsed packets CSV file.
        output_csv (str): Path to save the processed dataset.
    """
    # Step 1: Load the parsed packet data into a DataFrame
    df = pd.read_csv(input_csv)

    # Step 2: Encode categorical variables (e.g., protocol, IPs) into numerical values
    df["protocol_encoded"] = df["protocol"].astype("category").cat.codes
    df["src_ip_encoded"] = df["src_ip"].astype("category").cat.codes
    df["dst_ip_encoded"] = df["dst_ip"].astype("category").cat.codes

    # Step 3: Create labels for classification (0 = normal, 1 = suspicious)
    df["label"] = 0  # Default all rows to normal
    df.loc[df["size"] > 1500, "label"] = 1  # Mark packets larger than 1500 bytes as suspicious
    df.loc[df["protocol"].isin(["FTP", "Telnet"]), "label"] = 1  # Mark suspicious protocols

    # Step 4: Save the processed data to a new CSV file
    df.to_csv(output_csv, index=False)
    print(f"Processed dataset saved to {output_csv}")

# Function to train the machine learning model
def train_model(input_csv="reports/processed_data.csv", model_output="models/anomaly_detector.pkl"):
    """
    This function trains a Random Forest model to classify network packets as normal or suspicious.
    
    Args:
        input_csv (str): Path to the processed dataset CSV file.
        model_output (str): Path to save the trained model.
    """
    # Step 1: Load the processed dataset
    df = pd.read_csv(input_csv)

    # Step 2: Define the features (input variables) and labels (target variable)
    # Features: Protocol, source IP, destination IP, and packet size
    # Label: Normal (0) or suspicious (1)
    features = df[["protocol_encoded", "src_ip_encoded", "dst_ip_encoded", "size"]]
    labels = df["label"]

    # Step 3: Split the data into training and testing sets (80% training, 20% testing)
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    # Step 4: Train a Random Forest model with 100 decision trees
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)  # Fit the model to the training data
    print("Model trained successfully!")

    # Step 5: Evaluate the model on the test data
    y_pred = clf.predict(X_test)  # Predict the labels for the test set
    print("Classification Report:")  # Detailed performance metrics (precision, recall, F1-score)
    print(classification_report(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))  # Overall accuracy of the model

    # Step 6: Save the trained model to a file for future use
    joblib.dump(clf, model_output)
    print(f"Model saved to {model_output}")

# Main script execution
if __name__ == "__main__":
    # Step 1: Prepare the dataset
    prepare_data()
    
    # Step 2: Train the model
    train_model()
