""" REFERENCES 
[1] BlueWookie, “Python3 Scapy custom payload from string,” Stack Overflow, 2024. https://stackoverflow.com/questions/62642175/python3-scapy-custom-payload-from-string (accessed Sep. 15, 2024).
[2] E. Skoudis, “SANS Penetration Testing | SANS Pen Test Cheat Sheet: Scapy | SANS Institute,” www.sans.org, Apr. 05, 2016. https://www.sans.org/blog/sans-pen-test-cheat-sheet-scapy/ (accessed Sep. 9, 2024).
[3] “How to check if the string is empty in Python?,” Stack Overflow. https://stackoverflow.com/questions/9573244/how-to-check-if-the-string-is-empty-in-python (accessed Sep. 09, 2024).
[4] K. Kipsang, “Split and Strip Function in Python,” Medium, Jan. 11, 2023. https://medium.com/@kelvinsang97/split-and-strip-function-in-python-18e741c0bb75 (accessed Sep. 09, 2024).
[5] ‌Mr. Shickadance, “How to check for presence of a layer in a scapy packet?,” Stack Overflow, 2024. https://stackoverflow.com/questions/5540571/how-to-check-for-presence-of-a-layer-in-a-scapy-packet (accessed Sep. 14, 2024).
[6] N. Parlante, “Python main() - Command Line Arguments,” Stanford.edu, 2020. https://cs.stanford.edu/people/nick/py/python-main.html (accessed Sep. 9, 2024).
[7] “python - How do I append to a file?,” Stack Overflow. https://stackoverflow.com/questions/4706499/how-do-i-append-to-a-file (accessed Sep. 15, 2024).
[8] “python - Get TCP Flags with Scapy,” Stack Overflow. https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy (accessed Sep. 14, 2024).
[9] S. Reese, “Increment IP packet timestamp - Stephen Reese,” Rsreese.com, Mar. 13, 2013. https://www.rsreese.com/increment-ip-packet-timestamp/ (accessed Sep. 14, 2024).
[10] tutorials point, “Python time strftime() Method,” Tutorialspoint.com, 2023. https://www.tutorialspoint.com/python/time_strftime.htm (accessed Sep. 10, 2024).
"""

import sys
from scapy.all import rdpcap, TCP, UDP, ICMP, IP
import time

# Track packet timestamps for rules with detection_filter
packet_counters = {}

# Parse a simple IDS rule from the rule file
# [4]
def parse_rule(rule_line):
    parts = rule_line.split()
    
    # Extract the rule components
    if len(parts) > 7:
        action = parts[0] # alert
        protocol = parts[1] # protocol
        src_ip = parts[2] # Source IP
        src_port = parts[3] # Source Port
        # Ignore the '->' part
        dst_ip = parts[5] # Destination IP
        dst_port = parts[6] # Destination Port
    else:
        return {'action': None} # Bad formatting
    
    # Get alert message 
    try:
        message = rule_line.split('msg:')[1].split(';')[0].strip(' "')
    except:
        return {'action': None} # Bad formatting
    
    # Initialize optional fields    
    content = None
    flags = None
    count = None
    seconds = None
    
    # Check for and extract 'content' field
    if 'content:' in rule_line:
        try:
            content = rule_line.split('content:')[1].split(';')[0].strip(' "')
        except:
            pass # Bad formatting - ignore (assuming proper rules given)
    
    # Check for and extract 'flags' field
    if 'flags:' in rule_line:
        try:
            flags = rule_line.split('flags: ')[1].split(';')[0].strip()
        except:
            pass # Bad formatting - ignore (assuming proper rules given)

    # Check for and extract 'detection_filter' (count and seconds)
    if 'detection_filter:' in rule_line:
        try:
            filter_parts = rule_line.split('detection_filter:')[1].split(';')[0].strip()
            count = int(filter_parts.split('count')[1].split(',')[0].strip())
            seconds = int(filter_parts.split('seconds')[1].strip())
        except:
            pass # Bad formatting - ignore (assuming proper rules given)
    
    return {
        'action': action,
        'protocol': protocol,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'message': message,
        'content': content,
        'flags': flags,
        'count': count,
        'seconds': seconds
    }


# Match a packet against a rule
# [2 + 5]
def match_packet(packet, rule):
    if IP not in packet:
        # Return False if packet doesn't have an IP layer
        return False

    ip_layer = packet[IP]

    # Match source IP
    if rule['src_ip'] != 'any' and ip_layer.src != rule['src_ip']:
        return False

    # Match destination IP
    if rule['dst_ip'] != 'any' and ip_layer.dst != rule['dst_ip']:
        return False

    # Check protocol-specific matching
    if rule['protocol'] == 'tcp' and TCP in packet:
        pass # protocol match
    elif rule['protocol'] == 'udp' and UDP in packet:
        pass # protocol match
    elif rule['protocol'] == 'icmp' and ICMP in packet:
        pass # protocol match
    elif rule['protocol'] == 'ip': 
        pass # protocol match
    else:
        # If protocol doesn't match, return False
        return False
    
    # Check other values 
    answer = True 
    if TCP in packet:
        answer &= match_tcp_packet(packet, rule)
    if  UDP in packet:
        answer &= match_udp_packet(packet, rule)
    
    # Return match if no other data availible for checking
    return answer

# Match TCP packet with flags and ports
# [1 + 2 + 8]
def match_tcp_packet(packet, rule):
    tcp_layer = packet[TCP]

    # Match source port
    if rule['src_port'] != 'any' and tcp_layer.sport != int(rule['src_port']):
        return False

    # Match destination port
    if rule['dst_port'] != 'any' and tcp_layer.dport != int(rule['dst_port']):
        return False

    # Match TCP flags that exist
    if rule['flags']:
        tcp_flags = tcp_layer.flags
        # Handle 'A+', 'F+', 'S+', 'R+'
        if rule['flags'] == 'A+' and not tcp_flags & 0x10: #ACK flag
            return False
        if rule['flags'] == 'F+' and not tcp_flags & 0x01: #FIN flag
            return False
        if rule['flags'] == 'S+' and not tcp_flags & 0x02: #SYN flag
            return False
        if rule['flags'] == 'R+' and not tcp_flags & 0x04: #RST flag
            return False
        
        # Handle 'A', 'F', 'S', 'R'
        if rule['flags'] == 'A' and tcp_flags != 0x10: #ACK flag
            return False
        if rule['flags'] == 'F' and tcp_flags != 0x01: #FIN flag
            return False
        if rule['flags'] == 'S' and tcp_flags != 0x02: #SYN flag
            return False
        if rule['flags'] == 'R' and tcp_flags != 0x04: #RST flag
            return False

    # Match content (payload)
    if rule['content'] and rule['content'] not in str(packet[TCP].payload.load.decode("utf-8")):
        return False

    return True

# Match UDP packet with ports
# [1 + 2]
def match_udp_packet(packet, rule):
    udp_layer = packet[UDP]

    # Match source port
    if rule['src_port'] != 'any' and udp_layer.sport != int(rule['src_port']):
        return False

    # Match destination port
    if rule['dst_port'] != 'any' and udp_layer.dport != int(rule['dst_port']):
        return False

    # Match content (payload)
    if rule['content'] and rule['content'] not in str(packet[UDP].payload.load.decode("utf-8")):
        return False

    return True

# Handles packet detection (alerts if number of packets recieved in a specified 
#   period (from packet's timestamp) exceed specified quantity to be allowed)
# Note: called after packet has been matched
# [7 + 9 + 10]
def handle_detection_filter(packet, rule):
    global packet_counters
    packet_time = packet.time

    # Use rule message to identify packet rule (expected to be unique for each rule)
    rule_key = rule['message']

    if rule_key not in packet_counters:
        packet_counters[rule_key] = []

    # Add the current packet's timestamp
    packet_counters[rule_key].append(packet_time)

    # Count number of packets in timeframe window
    num_packets_in_window = 0
    for past_packet_time in packet_counters[rule_key]:
        if ((packet_time - past_packet_time) <= rule['seconds']):
            num_packets_in_window += 1

    # Check if more than allowed packets match the rule within the time window
    if num_packets_in_window > rule['count']:
        # Get current timestamp for the alert message
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    
        # Append the alert (with the timestamp and message) to IDS_log.txt
        with open("IDS_log.txt", "a") as log_file:  # Open file in append mode
            log_file.write(f"{timestamp} - Alert: {rule['message']}\n")

# Get a list of all the rules (dict) in the file
# [3]
def load_rules_from_file(rule_file):
    rules = []
    
    with open(rule_file, 'r') as f:
        for line in f:
            if line.strip(): # Checks not just an empty line
                if line.strip()[0] != '#': # Checks not a commented line
                    new_rule = parse_rule(line.strip()) # Parses rule

                    # Checks that rule is an alert (proper format) and adds to the rule list
                    if (new_rule['action'] == "alert"): 
                        rules += [new_rule]
    
    return rules

# Run everything 
# [6 + 7 + 10]
def main():
    # check required number of files are given
    if len(sys.argv) != 3:
        print("Usage: python3 IDS.py <path_to_the_pcap_file> <path_to_the_rule_file>")
        sys.exit(1)
    
    with open("IDS_log.txt", "w") as log_file:
        # Clear old file contents
        pass
    
    pcap_file = sys.argv[1] # pcap file
    rule_file = sys.argv[2]  # IDS rules file

    # Load rules from the rule file
    rules = load_rules_from_file(rule_file)
    
    # Load packets from the pcap file
    packets = rdpcap(pcap_file)
    
    # Check each packet against each rule
    for packet in packets:
        for rule in rules:
            if match_packet(packet, rule):
                # If the rule contains a 'detection_filter', handle it
                if rule['count'] and rule['seconds']:
                    handle_detection_filter(packet, rule)
                else:
                    # Get current timestamp (str format)
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Append the alert with the timestamp and message to IDS_log.txt
                    with open("IDS_log.txt", "a") as log_file:  # Open file in append mode
                        log_file.write(f"{timestamp} - Alert: {rule['message']}\n")

if __name__ == "__main__":
    main()
