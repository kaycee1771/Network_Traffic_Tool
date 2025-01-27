import pyshark
import pandas as pd
from detection import detect_anomalies, detect_traffic_spikes
from visualizer import plot_protocol_distribution, plot_suspicious_traffic, plot_top_suspicious_ips, map_suspicious_ips, get_geolocation
from joblib import load

# Load the pre-trained machine learning model
model_path = "models/anomaly_detector.pkl"
model = load(model_path)


def process_live_packets(interface, packet_size_limit, request_rate_limit, time_window, spike_threshold):
    """
    Captures live network traffic, processes packets, and detects anomalies or traffic spikes.

    Args:
        interface (str): Network interface to capture packets from.
        packet_size_limit (int): Threshold for large packet size in bytes.
        request_rate_limit (int): Maximum allowed requests per source IP.
        time_window (int): Time window (in seconds) for detecting traffic spikes.
        spike_threshold (int): Threshold for packets in the time window to classify as a spike.
    """
    print(f"Starting live capture on interface: {interface}")
    live_capture = pyshark.LiveCapture(interface=interface)
    live_data = []

    try:
        for packet in live_capture.sniff_continuously(packet_count=100):
            try:
                # Extract details from the packet
                packet_info = {
                    "timestamp": packet.sniff_time,
                    "src_ip": getattr(packet.ip, "src", "N/A"),
                    "dst_ip": getattr(packet.ip, "dst", "N/A"),
                    "protocol": packet.highest_layer,
                    "size": int(packet.length),
                }
                live_data.append(packet_info)
                print(f"Captured Packet: {packet_info}")

                # Process the data in batches of 50 packets
                if len(live_data) % 50 == 0:
                    df = pd.DataFrame(live_data)
                    detect_anomalies(df, packet_size_limit, request_rate_limit, output_report=None)
                    spike_ips = detect_traffic_spikes(df, time_window, spike_threshold)

                    if spike_ips:
                        df.loc[df["src_ip"].isin(spike_ips), "suspicious"] = True
                        df.loc[df["src_ip"].isin(spike_ips), "reason"] = "Traffic spike detected"

                    plot_protocol_distribution(df, output_path="reports/live_protocol_distribution.png")
                    plot_suspicious_traffic(df, output_path="reports/live_suspicious_traffic.png")
                    plot_top_suspicious_ips(df, output_path="reports/live_top_suspicious_ips.png")
                    live_data = []

            except AttributeError:
                # Skip packets with missing attributes
                continue
    except KeyboardInterrupt:
        print("Stopping live capture...")


def process_live_packets_with_ml(interface, model_path, output_log="reports/live_suspicious_traffic.csv"):
    """
    Captures live network traffic and detects anomalies using a pre-trained machine learning model.

    Args:
        interface (str): Network interface to capture packets from.
        model_path (str): Path to the trained machine learning model.
        output_log (str): Path to save detected suspicious traffic.
    """
    model = load(model_path)
    print(f"Loaded model from {model_path}")

    live_capture = pyshark.LiveCapture(interface=interface)
    live_data = []

    print(f"Starting live capture on interface: {interface}")
    for packet in live_capture.sniff_continuously(packet_count=1000):
        try:
            if not hasattr(packet, "ip"):
                continue

            packet_info = {
                "timestamp": packet.sniff_time,
                "src_ip": getattr(packet.ip, "src", "N/A"),
                "dst_ip": getattr(packet.ip, "dst", "N/A"),
                "protocol": packet.highest_layer,
                "size": int(packet.length),
            }
            live_data.append(packet_info)

            if len(live_data) % 50 == 0:
                df = pd.DataFrame(live_data)
                df["protocol_encoded"] = df["protocol"].astype("category").cat.codes
                df["src_ip_encoded"] = df["src_ip"].astype("category").cat.codes
                df["dst_ip_encoded"] = df["dst_ip"].astype("category").cat.codes

                df["ml_prediction"] = model.predict(
                    df[["protocol_encoded", "src_ip_encoded", "dst_ip_encoded", "size"]]
                )
                df["suspicious"] = df["ml_prediction"] == 1

                suspicious_traffic = df[df["suspicious"]]
                if not suspicious_traffic.empty:
                    suspicious_traffic.to_csv(output_log, mode="a", header=False, index=False)
                    print(f"Logged {len(suspicious_traffic)} suspicious packets.")

                live_data = []
        except Exception as e:
            print(f"Error processing packet: {e}")


if __name__ == "__main__":
    # Parameters for testing live capture
    interface = "WiFi"  # Replace with your network interface (e.g., "Wi-Fi" or "en0")
    packet_size_limit = 1500
    request_rate_limit = 100
    time_window = 5
    spike_threshold = 50

    process_live_packets_with_ml(interface, model_path)
    process_live_packets(interface, packet_size_limit, request_rate_limit, time_window, spike_threshold)
