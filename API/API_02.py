from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import threading
import time

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize packet counts as global variables
current_packet_counts = {}

# Function to calculate packet counts and last IP addresses
def calculate_packet_counts(filename):
    # Read the CSV file into a DataFrame using pandas
    df = pd.read_csv(filename)

    # Count the number of TCP and UDP packets
    tcp_packets = df[df['PROTOCOL'] == 'TCP'].shape[0]
    udp_packets = df[df['PROTOCOL'] == 'UDP'].shape[0]
    icmp_packets = df[df['SERVICE_TYPE'] == 'ICMP'].shape[0]
    http_packets = df[df['SERVICE_TYPE'] == 'HTTP'].shape[0]
    https_packets = df[df['SERVICE_TYPE'] == 'HTTPS'].shape[0]
    dns_packets = df[df['SERVICE_TYPE'] == 'DNS'].shape[0]
    smtp_packets = df[df['SERVICE_TYPE'] == 'SMTP'].shape[0]
    telnet_packets = df[df['SERVICE_TYPE'] == 'TELNET'].shape[0]
    total_packets = len(df)

    # Get the last SRC-IP and DST-IP addresses
    src_ip = df.iloc[-1]['SRC-IP']
    dst_ip = df.iloc[-1]['DST-IP']
    typ = df.iloc[-1]['PROTOCOL']
    

    return {
        'tcp_packets': tcp_packets,
        'udp_packets': udp_packets,
        'icmp_packets': icmp_packets,
        'http_packets': http_packets,
        'https_packets': https_packets,
        'dns_packets': dns_packets,
        'smtp_packets': smtp_packets,
        'telnet_packets': telnet_packets,
        'total_packets': total_packets,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'typ' : typ
    }

# Function to update packet counts
def update_packet_counts(filename):
    global current_packet_counts
    while True:
        packet_counts = calculate_packet_counts(filename)
        current_packet_counts = packet_counts
        # Optionally, you can store or process the packet counts here
        print(packet_counts)
        # Sleep for a certain interval before updating counts again
        time.sleep(2)  # Adjust the interval as needed

# Endpoint to trigger the update of packet counts
@app.route('/api/packet-report', methods=['GET'])
def trigger_update_packet_counts():
    global current_packet_counts
    filename = '/home/kali/Desktop/XXXXx/project/malicious.csv'  # Adjust file path
    packet_counts = calculate_packet_counts(filename)
    current_packet_counts = packet_counts
    return jsonify(current_packet_counts)

# Endpoint to get packet counts
@app.route('/api/packet-reports', methods=['GET'])
def get_packet_counts():
    global current_packet_counts
    # Provide the current packet counts (you may implement caching or another mechanism here)
    return jsonify(current_packet_counts)

if __name__ == '__main__':
    filename = '/home/kali/Desktop/XXXXx/project/malicious.csv'  # Adjust file path

    # Start a thread to continuously update packet counts
    packet_count_thread = threading.Thread(target=update_packet_counts, args=(filename,))
    packet_count_thread.daemon = True  # Daemonize the thread to exit with the main program
    packet_count_thread.start()

    # Run the Flask app in the main thread
    app.run(debug=True, host='0.0.0.0',port=8000)
