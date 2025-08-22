import os #access to my system
import subprocess #to run tshark command
import sys #to handle system exit
import argparse #to handle command line arguments

import dpkt #packet analysis library
import socket #to handle IP addresses, convert them to human-readable format
import matplotlib.pyplot as plt #for plotting graphs

def capture_traffic(client_ip, server_ip, interface, duration, filename):
    capture_filter = f"host {client_ip}" #for tshark filter

    #list of arguments passed to os
    command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",  # Capture for a specified duration
        "-f", capture_filter,  # Apply the capture filter
        "-F", "pcap",           # Force legacy pcap format
        "-w", filename  # Write output to a file
    ]

    try:
        subprocess.run(
            command,
            check=True,  # Raise an error if the command fails
            capture_output=True  # Capture stdout and stderr
        )
        return True
    except FileNotFoundError:
        print("'tshark' command not found.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error during capture")
        print(e.stderr.decode())
        return False
    except KeyboardInterrupt:
        print("Capture stopped by user.")
        return False

def analyse_throughput(filename, client_ip, server_ip, down=False, up=False):
    if down:
        direction_str = "Download"
        src_ip_check, dst_ip_check = server_ip, client_ip
        plot_filename = "down_throughput.png"
    else: # up
        direction_str = "Upload"
        src_ip_check, dst_ip_check = client_ip, server_ip
        plot_filename = "up_throughput.png"

    throughput = {} #second: bytes
    print(f"Analyzing {direction_str} traffic from {src_ip_check} to {dst_ip_check}")
    
    try:
        with open(filename, 'rb') as f: #opening non-text file
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                #os presents packets in virtual ethernet format
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                #ensure the packet is an IP packet
                #there may be non-ip traffic like ARP
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                    
                src_addr, dst_addr = None, None
                
                # Check if the packet is IPv4
                if isinstance(ip, dpkt.ip.IP):
                    src_addr = socket.inet_ntop(socket.AF_INET, ip.src)
                    dst_addr = socket.inet_ntop(socket.AF_INET, ip.dst)
                # Else, check if it's IPv6
                elif isinstance(ip, dpkt.ip6.IP6):
                    src_addr = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_addr = socket.inet_ntop(socket.AF_INET6, ip.dst)

                #check if the packet is from the client to the server or vice versa
                if (src_addr == src_ip_check and dst_addr == dst_ip_check):
                    # Count bytes for throughput
                    discrete_int_time = int(timestamp)

                    if isinstance(ip, dpkt.ip.IP):       # IPv4
                        pkt_len = ip.len
                    elif isinstance(ip, dpkt.ip6.IP6):   # IPv6
                        pkt_len = ip.plen + 40  # payload length + IPv6 header (fixed 40 bytes)
                    else:
                        pkt_len = len(buf)  # fallback

                    throughput[discrete_int_time] = throughput.get(discrete_int_time, 0) + pkt_len


    except Exception as e:
        print(f"Error reading pcap file: {e}")

    # Plot the throughput graph        
    plt.figure()
    sorted_times = sorted(throughput.keys())
    sorted_values = [throughput[t] for t in sorted_times]
    plt.plot(sorted_times, sorted_values)
    plt.title(f"{direction_str} Throughput")
    plt.xlabel("Time (s)")
    plt.ylabel("Bytes")
    plt.savefig(plot_filename)
    plt.close()
    print(f"{direction_str} throughput plot saved to {plot_filename}")


def analyse_rtt(filename, client_ip, server_ip):
    plot_filename = "rtt.png"

    ## This tracks data packets sent from the client for which we await an ACK.
    sent_packets = {}  # expected_ack: timestamp
    rtt_values = []  # list of RTT values (ack_time, calculated_rtt)
    try:
        with open(filename, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap:
                    
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                # Ensure the packet is an IP packet
                # Consider both IPv4 and IPv6
                # and ensure it contains TCP data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                    
                tcp = ip.data

                src_addr, dst_addr = None, None
                if isinstance(ip, dpkt.ip.IP):
                    src_addr = socket.inet_ntop(socket.AF_INET, ip.src)
                    dst_addr = socket.inet_ntop(socket.AF_INET, ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    src_addr = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_addr = socket.inet_ntop(socket.AF_INET6, ip.dst)

                #uplink
                if src_addr == client_ip and dst_addr == server_ip and len(tcp.data) > 0:
                    # Expected ACK number is seq + payload length
                    expected_ack = tcp.seq + len(tcp.data)

                    # Track when the packet was sent (based on TCP data length, not headers)
                    sent_packets[expected_ack] = timestamp


                #downlink
                elif src_addr == server_ip and dst_addr == client_ip and tcp.flags & dpkt.tcp.TH_ACK:
                    ack_num = tcp.ack

                    if ack_num in sent_packets:
                        sent_time = sent_packets[ack_num]
                        rtt = timestamp - sent_time
                        rtt_values.append((timestamp, rtt))
                        del sent_packets[ack_num]

    except Exception as e:
        print(f"Error reading pcap file: {e}")

    if rtt_values:
        ack_times, rtt_values = zip(*rtt_values)

        plt.figure()
        plt.scatter(ack_times, rtt_values, marker='o')
        plt.title("RTT for Uplink TCP Traffic")
        plt.xlabel("Time of ACK Received (s)")
        plt.ylabel("Round-Trip Time (s)")
        plt.grid(True)
        plt.savefig(plot_filename)
        plt.close()
        print(f"RTT plot saved to {plot_filename}")
    else:
        print("No RTT samples could be calculated.")



if __name__ == "__main__":
    #using argparse to handle command line inputs
    #it detects missing arguments and useful in writing help text
    parser = argparse.ArgumentParser(description="Isolate and capture web traffic between a client and a server using tshark.")

    parser.add_argument("--client", required=True, help="Provide client ip")
    parser.add_argument("--server", required=True, help="Provide Server ip")
    parser.add_argument("--file", default="traffic.pcap", help="Output filename for captured traffic (default: 'traffic.pcap').")

    parser.add_argument("--throughput", action='store_true')
    parser.add_argument("--down", action='store_true')
    parser.add_argument("--up", action='store_true')

    parser.add_argument("--rtt", action='store_true')
    args = parser.parse_args()

    #if file not given, collect traffic
    if not os.path.exists(args.file):
        interface = "en0"  # Default interface, change as needed
        duration = 60  # Capture for 1 minute
        print("Visit the ip of server in your browser to generate traffic.")
        if not capture_traffic(args.client, args.server, interface, duration, args.file):
            print("Traffic capture failed. Exiting.")
            sys.exit(1)


    if args.throughput:
        analyse_throughput(args.file, args.client, args.server, args.down, args.up)
    elif args.rtt:
        analyse_rtt(args.file, args.client, args.server)
    else:
        print("No analysis option selected. Use --throughput or --rtt to analyze the captured traffic.")
