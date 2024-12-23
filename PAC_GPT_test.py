import random
import re

import openai

from scapy.all import Raw
from scapy.utils import RawPcapReader, wrpcap

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP
sample_gen_num = 100
def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    interesting_packet_count = 0

    interesting_packets = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 1:
            # Ignore non-TCP packet
            continue
        interesting_packet_count += 1
        interesting_packets.append(ether_pkt)

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))

    return interesting_packets

packets_scapy = process_pcap("/mnt/backups/yuwei/SAT-01-12-2018_0817.pcap")

with open("ping_summaries.txt","r") as f:
    packets_summary = f.read().splitlines()

packets = tuple(zip(packets_summary,packets_scapy))
engines = openai.Engine.list()

responses = []
for i in range(sample_gen_num):
    summary,packet = random.choice(packets)
    packet = packet[IP]
    try:
        del packet[Raw]
    except IndexError:
        packet.show()
    del packet.chksum
    del packet[ICMP].chksum
    query = "This is the packet summary:\n"
    query += summary + "\n\n"
    query += "This is the packet details:\n"
    query += str(packet.show(dump=True))
    
    summary,_ = random.choice(packets)
    query += "\n\nThis is another packet summary:\n"
    query += summary + "\n\n"
    query += "Generate the packet details."
    
    print(query)
    break
    
    completion = openai.Completion.create(engine="text-davinci-003", prompt=query,max_tokens=3500)
    completion["prompt_summary"] = summary
    responses.append(completion)

print(len(responses))

print(responses[0].prompt_summary)
print(responses[0].choices[0].text)

def str_to_packet(s):
    packet = IP()
    s2i_proto = {v:k for k,v in packet.get_field("proto").i2s.items()}
    _,ip_text,payload_text = re.split("\#{3}\[\s*\w*\s*\]\#{3}",s)
    for line in ip_text.splitlines():
        if line == " " or line == "  \\options   \\":
            continue

        try: 
            key,value = line.split("=")
        except ValueError:
            print(line)
            continue
        if key.strip() == "proto":
            packet[IP].proto = s2i_proto[value.strip()]
            continue
        try:
            packet[IP].fields[key.strip()] = int(value.strip(),0)
        except:
            
            packet[IP].fields[key.strip()] = value.strip()
    # Handle ICMP Payload 
    if packet[IP].proto == 1:
        packet = packet / ICMP()
        type_conversion = {"echo-reply" : 0, "echo-request":8}
        for line in payload_text.splitlines():
            if line == " " or line == "  \\options   \\":
                continue
                
            try: 
                key,value = line.split("=")
            except ValueError:
                print(line)
                continue
            
            try:
                packet[ICMP].fields[key.strip()] = int(value.strip(),0)
            except:
                packet[ICMP].fields[key.strip()] = value.strip()

        if packet.unused == "''":
            packet.unused = b''
        packet.type = type_conversion[packet.type]
    return packet
gen_pkts = [str_to_packet(response.choices[0].text) for response in responses]

def delete_wrong_fields(pkt):

    del pkt[IP].flags
    del pkt[IP].chksum
    del pkt[ICMP].chksum
    
    return pkt
    
gen_pkts = list(map(delete_wrong_fields,gen_pkts))
gen_pkts[0].show2()

with open("generated_icmp.pcap", "wb") as f:
    wrpcap(f, gen_pkts)

print(responses[0].choices[0].text)


summary,packet = random.choice(packets)

packet.show()

type(gen_pkts[0][ICMP].unused) == type(packet[ICMP].unused)


summary,packet2 = random.choice(packets)
packet2[IP].show()
packet2[IP].flags = "DF"
del packet2[Raw]
del packet2[IP].chksum
del packet2[ICMP].chksum
packet2[IP].show()
