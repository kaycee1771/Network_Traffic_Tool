import pandas as pd
import matplotlib.pyplot as plt
import folium
import requests

# Function to plot the distribution of protocols in the dataset
def plot_protocol_distribution(df, output_path="reports/protocol_distribution.png"):
    protocol_counts = df["protocol"].value_counts()
    plt.figure(figsize=(8, 6))
    protocol_counts.plot(kind="pie", autopct="%1.1f%%", startangle=140, colormap="viridis")
    plt.title("Protocol Distribution")
    plt.ylabel("")
    plt.savefig(output_path)
    plt.close()
    print(f"Saved protocol distribution plot to {output_path}")

# Function to plot the volume of suspicious traffic over time
def plot_suspicious_traffic(df, output_path="reports/suspicious_traffic_over_time.png"):
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    suspicious_traffic = df[df["suspicious"]]

    if suspicious_traffic.empty:
        print("No suspicious traffic to plot.")
        return

    suspicious_traffic.set_index("timestamp", inplace=True)
    plt.figure(figsize=(10, 6))
    suspicious_traffic["size"].resample("1min").sum().plot(kind="line", marker="o", colormap="viridis")
    plt.title("Suspicious Traffic Over Time")
    plt.xlabel("Time")
    plt.ylabel("Total Packet Size (bytes)")
    plt.grid(True)
    plt.savefig(output_path)
    plt.close()
    print(f"Saved suspicious traffic plot to {output_path}")

# Function to plot the top 10 source IPs with the most suspicious activity
def plot_top_suspicious_ips(df, output_path="reports/top_suspicious_ips.png"):
    top_ips = df[df["suspicious"]]["src_ip"].value_counts().head(10)
    if top_ips.empty:
        print("No suspicious IPs to plot.")
        return
    plt.figure(figsize=(10, 6))
    top_ips.plot(kind="bar", colormap="viridis")
    plt.title("Top Suspicious IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Suspicious Activity Count")
    plt.xticks(rotation=45)
    plt.grid(axis="y")
    plt.savefig(output_path)
    plt.close()
    print(f"Saved top suspicious IPs plot to {output_path}")

# Function to get the geolocation of an IP address using an external API
def get_geolocation(ip_address):
    """
    Fetches geolocation data for an IP address using ip-api.com.

    Args:
        ip_address (str): The IP address to locate.

    Returns:
        tuple: Latitude and longitude as (lat, lon), or None if not found.
    """
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url)
        data = response.json()
        if data["status"] == "success":
            return data["lat"], data["lon"]
        else:
            print(f"Geolocation not found for IP: {ip_address}")
    except Exception as e:
        print(f"Error fetching geolocation for {ip_address}: {e}")
    return None

# Function to create a map with markers for suspicious IPs
def map_suspicious_ips(suspicious_traffic_csv, output_map="reports/suspicious_ips_map.html"):
    """
    Creates a map with markers for suspicious IPs.

    Args:
        suspicious_traffic_csv (str): Path to the CSV file containing suspicious traffic data.
        output_map (str): Path to save the generated map HTML file.
    """
    df = pd.read_csv(suspicious_traffic_csv)
    traffic_map = folium.Map(location=[0, 0], zoom_start=2)

    unique_ips = pd.concat([df["src_ip"], df["dst_ip"]]).unique()

    for ip in unique_ips:
        location = get_geolocation(ip)
        if location:
            lat, lon = location
            folium.Marker(
                location=[lat, lon],
                popup=f"IP: {ip}",
                icon=folium.Icon(color="red" if ip in df["src_ip"].values else "blue", icon="info-sign"),
            ).add_to(traffic_map)

    traffic_map.save(output_map)
    print(f"Saved IP geolocation map to {output_map}")

# Example usage
if __name__ == "__main__":
    suspicious_traffic_csv = "reports/suspicious_traffic.csv"

    df = pd.read_csv(suspicious_traffic_csv)
    plot_protocol_distribution(df)
    plot_suspicious_traffic(df)
    plot_top_suspicious_ips(df)
    map_suspicious_ips(suspicious_traffic_csv)
