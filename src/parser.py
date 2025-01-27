import pyshark
import pandas as pd
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def parse_pcap(input_pcap, output_csv):
    """
    Parses a PCAP file to extract network packet details and saves them to a CSV file.

    Args:
        input_pcap (str): Path to the input PCAP file.
        output_csv (str): Path to the output CSV file.
    """
    try:
        logging.info(f"Loading PCAP file: {input_pcap}")
        capture = pyshark.FileCapture(input_pcap, use_json=True, include_raw=True)

        packets_data = []  # List to store packet details

        for packet in capture:
            try:
                # Extract general packet information
                timestamp = packet.sniff_time
                src_ip = packet.ip.src if hasattr(packet, 'ip') else None
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
                src_mac = packet.eth.src if hasattr(packet, 'eth') else None
                dst_mac = packet.eth.dst if hasattr(packet, 'eth') else None
                protocol = packet.highest_layer
                size = int(packet.length)
                hostname = None

                # Extract hostname from DNS queries
                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    hostname = packet.dns.qry_name

                # Append packet details to the list
                packets_data.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'protocol': protocol,
                    'size': size,
                    'hostname': hostname
                })
            except AttributeError as e:
                logging.warning(f"Error processing packet: {e}")

        # Convert the data into a DataFrame and save to CSV
        df = pd.DataFrame(packets_data)
        df.to_csv(output_csv, index=False)
        logging.info(f"Parsed packets saved to {output_csv}")

    except Exception as e:
        logging.error(f"Failed to parse PCAP file: {e}")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Enhanced PCAP Parser")
    parser.add_argument("--input_pcap", type=str, required=True, help="Path to the input PCAP file")
    parser.add_argument("--output_csv", type=str, required=True, help="Path to the output CSV file")
    args = parser.parse_args()

    # Execute the PCAP parsing function
    parse_pcap(args.input_pcap, args.output_csv)
