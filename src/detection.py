import pandas as pd
import argparse
import logging
from datetime import datetime
from joblib import load
from visualizer import (
    plot_protocol_distribution,
    plot_suspicious_traffic,
    plot_top_suspicious_ips,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load pre-trained ML model
MODEL_PATH = "models/anomaly_detector.pkl"
try:
    model = load(MODEL_PATH)
    logging.info(f"Loaded machine learning model from {MODEL_PATH}")
except FileNotFoundError:
    logging.error(f"Model file not found at {MODEL_PATH}. Train the model first!")
    exit()

def parse_lan_segment(df, lan_prefix):
    """
    Filters packets to identify traffic within the specified LAN segment.

    Args:
        df (DataFrame): Parsed packet data.
        lan_prefix (str): Prefix of the LAN IP range to filter (e.g., "192.168.0").

    Returns:
        DataFrame: Filtered packets within the LAN segment.
    """
    lan_traffic = df[
        (df["src_ip"].str.startswith(lan_prefix)) | 
        (df["dst_ip"].str.startswith(lan_prefix))
    ]
    return lan_traffic

def identify_infected_client(df, exclude_ips):
    """
    Identifies the most likely infected client based on LAN traffic patterns.

    Args:
        df (DataFrame): Filtered LAN traffic data.
        exclude_ips (list): IPs to exclude from infected client detection.

    Returns:
        dict: Information about the infected client.
    """
    try:
        suspect_traffic = df[~df["src_ip"].isin(exclude_ips)]
        infected_ip = suspect_traffic["src_ip"].value_counts().idxmax()
        infected_mac = df[df["src_ip"] == infected_ip]["src_mac"].dropna().iloc[0]
        hostname = df[df["src_ip"] == infected_ip]["src_hostname"].dropna().iloc[0]
        return {
            "infected_ip": infected_ip,
            "infected_mac": infected_mac,
            "hostname": hostname,
        }
    except Exception as e:
        logging.warning(f"Failed to identify infected client: {e}")
        return {}

def identify_c2_servers(df):
    """
    Identifies Command-and-Control (C2) server IPs from suspicious traffic.

    Args:
        df (DataFrame): Parsed packet data.

    Returns:
        list: List of unique C2 server IPs.
    """
    try:
        c2_servers = df[df["suspicious"]]["dst_ip"].unique().tolist()
        return c2_servers
    except KeyError as e:
        logging.error(f"Failed to identify C2 servers: {e}")
        return []

def detect_anomalies_with_ml(df, model, output_report=None):
    """
    Detect anomalies in network traffic using both heuristics and machine learning.

    Args:
        df (DataFrame): Parsed packet data.
        model (sklearn model): Pre-trained anomaly detection model.
        output_report (str): Path to save the suspicious traffic report.

    Returns:
        DataFrame: Updated DataFrame with anomaly detection results.
    """
    if df.empty:
        logging.warning("No data available for analysis.")
        return df

    # Add default heuristic detection flags
    df["suspicious"] = False
    df["reason"] = ""

    # Rule 1: Large Packets
    df.loc[df["size"] > 1500, "suspicious"] = True
    df.loc[df["size"] > 1500, "reason"] = "Unusually large packet size"

    # Rule 2: Suspicious Protocols
    df.loc[df["protocol"].isin(["FTP", "Telnet"]), "suspicious"] = True
    df.loc[df["protocol"].isin(["FTP", "Telnet"]), "reason"] = "Suspicious protocol"

    # Encode categorical features for ML
    df["protocol_encoded"] = df["protocol"].astype("category").cat.codes
    df["src_ip_encoded"] = df["src_ip"].astype("category").cat.codes
    df["dst_ip_encoded"] = df["dst_ip"].astype("category").cat.codes

    # Predict anomalies using the ML model
    df["ml_prediction"] = model.predict(df[["protocol_encoded", "src_ip_encoded", "dst_ip_encoded", "size"]])

    # Combine heuristic and ML-based detection
    df["suspicious"] = df["suspicious"] | (df["ml_prediction"] == 1)
    df.loc[df["ml_prediction"] == 1, "reason"] += "; ML anomaly detected"

    # Save suspicious traffic report
    if output_report:
        suspicious_traffic = df[df["suspicious"]]
        if not suspicious_traffic.empty:
            suspicious_traffic.to_csv(output_report, index=False)
            logging.info(f"Suspicious traffic report saved to {output_report}")
        else:
            logging.info("No suspicious traffic detected to save.")

    return df

def summarize_findings(infected_client, c2_servers):
    """
    Prints a summary of findings including the infected client and identified C2 servers.

    Args:
        infected_client (dict): Information about the infected client.
        c2_servers (list): List of C2 server IPs.
    """
    print("\n==== Incident Summary ====")
    if infected_client:
        print(f"Infected Client IP: {infected_client.get('infected_ip', 'N/A')}")
        print(f"Infected Client MAC: {infected_client.get('infected_mac', 'N/A')}")
        print(f"Hostname: {infected_client.get('hostname', 'N/A')}")
    else:
        print("No infected client identified.")
    print(f"C2 Server IPs: {', '.join(c2_servers) if c2_servers else 'None'}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Traffic Detection Tool with ML Integration")
    parser.add_argument("--input_file", type=str, default="reports/parsed_packets.csv", help="Input parsed packet data file")
    parser.add_argument("--output_report", type=str, default="reports/suspicious_traffic.csv", help="Output suspicious traffic report")
    parser.add_argument("--lan_prefix", type=str, default="192.168.0", help="LAN segment prefix to filter traffic")
    args = parser.parse_args()

    # Load the parsed data
    try:
        df = pd.read_csv(args.input_file)
        logging.info(f"Loaded parsed data from {args.input_file}")
    except FileNotFoundError:
        logging.error(f"Parsed data file not found: {args.input_file}")
        exit()

    # Filter LAN segment traffic
    lan_traffic = parse_lan_segment(df, lan_prefix=args.lan_prefix)

    # Identify the infected client
    infected_client = identify_infected_client(lan_traffic, exclude_ips=[f"{args.lan_prefix}.1", f"{args.lan_prefix}.255"])
    if infected_client:
        logging.info(f"Infected Client Details: {infected_client}")

    # Detect anomalies (heuristics + ML)
    df = detect_anomalies_with_ml(df, model, output_report=args.output_report)

    # Identify C2 servers
    c2_servers = identify_c2_servers(df)
    logging.info(f"Identified C2 Servers: {c2_servers}")

    # Summarize findings
    summarize_findings(infected_client, c2_servers)

    # Generate Visualizations
    plot_protocol_distribution(df, output_path="reports/protocol_distribution.png")
    plot_suspicious_traffic(df, output_path="reports/suspicious_traffic.png")
    plot_top_suspicious_ips(df, output_path="reports/top_suspicious_ips.png")
    logging.info("Visualizations generated.")
