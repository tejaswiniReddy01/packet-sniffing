import plotly.graph_objects as go
from plotly.subplots import make_subplots
from scapy.all import sniff, wrpcap
import time
from collections import deque, Counter
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize a deque to hold packet timestamps and packet details
packet_timestamps = deque()
packet_details = []
max_timestamps = 1000  # Maximum number of timestamps to store for visualization

def packet_callback(packet):
    # Capture the timestamp and details of each packet
    packet_timestamps.append(time.time())
    packet_details.append(packet)
    if len(packet_timestamps) > max_timestamps:
        packet_timestamps.popleft()
        packet_details.pop(0)

def visualize_traffic():
    if not packet_timestamps:
        logging.info("No packets captured. No data to visualize.")
        return
    
    # Create a simple plot
    fig = go.Figure()
    
    # Packet count over time
    start_time = packet_timestamps[0]
    relative_times = [t - start_time for t in packet_timestamps]
    fig.add_trace(go.Histogram(x=relative_times, nbinsx=30, name="Packet Count"))
    
    # Update layout
    fig.update_layout(
        title_text="Network Traffic Analysis",
        xaxis_title="Time Since Start (seconds)",
        yaxis_title="Number of Packets",
        height=600,
        width=800
    )
    
    # Save the plot to an HTML file and open it in a browser
    import plotly.offline as pyo
    pyo.plot(fig, filename='network_traffic_analysis.html', auto_open=True)

def sniff_packets(duration, filter_criteria, output_file):
    logging.info("Starting packet sniffing...")
    packets = sniff(prn=packet_callback, filter=filter_criteria, store=True, timeout=duration)
    logging.info("Packet sniffing completed.")
    if output_file:
        wrpcap(output_file, packets)
        logging.info(f"Captured packets saved to {output_file}")

def get_filter_criteria(choice):
    if choice == 1:
        return "ip"
    elif choice == 2:
        return "tcp"
    elif choice == 3:
        return "udp"
    elif choice == 4:
        return "arp"
    elif choice == 5:
        return "icmp"
    elif choice == 6:
        return "port 53"  # DNS usually uses port 53
    else:
        return ""

def packet_analysis():
    if not packet_details:
        logging.info("No packets captured. No data to analyze.")
        return
    
    # Count packets by protocol
    protocol_counter = Counter()
    for packet in packet_details:
        protocol = packet.proto if hasattr(packet, 'proto') else 'Unknown'
        protocol_counter[protocol] += 1
    
    logging.info("Packet Analysis:")
    for protocol, count in protocol_counter.items():
        logging.info(f"{protocol}: {count} packets")
    
    # Display unique source IP addresses
    src_ips = [packet.src for packet in packet_details if hasattr(packet, 'src')]
    unique_ips = set(src_ips)
    logging.info(f"Unique source IP addresses: {unique_ips}")

def main():
    duration = 60  # Duration of packet sniffing in seconds
    output_file = "captured_packets.pcap"
    
    print("Select the type of packets to capture:")
    print("1. IP")
    print("2. TCP")
    print("3. UDP")
    print("4. ARP")
    print("5. ICMP")
    print("6. DNS")
    choice = int(input("Enter your choice (1/2/3/4/5/6): "))
    
    filter_criteria = get_filter_criteria(choice)
    if not filter_criteria:
        logging.error("Invalid choice. Exiting.")
        return
    
    sniff_thread = threading.Thread(target=sniff_packets, args=(duration, filter_criteria, output_file))
    sniff_thread.start()
    
    sniff_thread.join()
    
    visualize_traffic()
    packet_analysis()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nStopping packet sniffing...")
        visualize_traffic()
        packet_analysis()

