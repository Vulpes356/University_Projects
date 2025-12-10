#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# sniffer.py (Updated with MQTT Flow Features)
# - 5-tuple flows (bidirectional) + 10-packet window aggregation
# - Posts features including MQTT specifics under {"flows":[...]}
# - Hardcoded: iface=ens33, ML_URL=http://172.28.100.4:8000/ingest_flow

import os
import sys
import time
import math
from collections import Counter, deque

import numpy as np
import requests
# Import Scapy and MQTT contrib
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, bind_layers
from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish, MQTTSubscribe

INTERFACE = os.environ.get("SNIFFER_IFACE", "ens33")
ML_URL    = os.environ.get("ML_URL", "http://172.28.100.4:8000/ingest_flow")
WINDOW_SIZE = 100
CONNECT_TIMEOUT = 5.0

def make_flow_key(ip_src, sport, ip_dst, dport):
    a = (ip_src, int(sport) if sport is not None else 0)
    b = (ip_dst, int(dport) if dport is not None else 0)
    return (a, b) if a <= b else (b, a)

class FlowState:
    __slots__ = ("start_ts","last_ts","fwd_pkts","bwd_pkts","fwd_bytes","bwd_bytes")
    def __init__(self, ts):
        self.start_ts = ts
        self.last_ts  = ts
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes= 0
        self.bwd_bytes= 0
    def update(self, ts, direction, pkt_len):
        self.last_ts = ts
        if direction == "fwd":
            self.fwd_pkts += 1; self.fwd_bytes += pkt_len
        else:
            self.bwd_pkts += 1; self.bwd_bytes += pkt_len
    def duration(self):
        return max(0.0, self.last_ts - self.start_ts)

tcpflows = {}
udpflows = {}
packet_buf = deque(maxlen=WINDOW_SIZE)

def header_len_tcp(tcp):
    try: return int(tcp.dataofs) * 4
    except Exception: return 20

def compute_header_len(pkt):
    base = 20
    if TCP in pkt: return base + header_len_tcp(pkt[TCP])
    if UDP in pkt: return base + 8
    if ICMP in pkt: return base + 8
    return base

def detect_l7_by_port(sport, dport):
    ports = {sport, dport}
    http  = int(80 in ports)
    https = int(443 in ports)
    dns   = int(53 in ports)
    tel   = int(23 in ports)
    smtp  = int(25 in ports or 587 in ports)
    ssh   = int(22 in ports)
    irc   = int(6667 in ports or 194 in ports or 21 in ports)
    dhcp  = int(67 in ports or 68 in ports)
    return http, https, dns, tel, smtp, ssh, irc, dhcp

def dynamic_two_streams(inco_sizes, out_sizes):
    inco = np.array(inco_sizes, dtype=float) if inco_sizes else np.array([0.0])
    outg = np.array(out_sizes, dtype=float)  if out_sizes  else np.array([0.0])
    inco_ave = float(np.mean(inco)); outg_ave = float(np.mean(outg))
    inco_var = float(np.var(inco));  outg_var = float(np.var(outg))
    magnitue = float(math.sqrt(max(0.0, inco_ave + outg_ave)))
    radius   = float(math.sqrt(max(0.0, inco_var + outg_var)))
    m = min(len(inco), len(outg))
    if m >= 2:
        cov = float(np.cov(inco[:m], outg[:m])[0,1])
    else:
        cov = 0.0
    weight = float(len(inco) * len(outg))
    return magnitue, radius, cov, weight

def packet_to_row(pkt, ts):
    size = int(len(pkt))
    proto = 0
    flags = {"fin":0,"syn":0,"rst":0,"psh":0,"ack":0,"urg":0,"ece":0,"cwr":0}
    sport = dport = 0
    http=https=dns=tel=smtp=ssh=irc=dhcp=0
    tcp=udp=icmp=ipv=arp=llc=0
    src=dst=None
    fk_tcp = None; fk_udp = None

    # --- MQTT Raw Feature Variables ---
    mqtt_type = 0
    mqtt_len = 0
    mqtt_topic_len = 0
    mqtt_rc = 0
    mqtt_dirty = 0
    mqtt_will = 0
    # ----------------------------------

    if ARP in pkt: arp = 1
    if IP in pkt:
        ipv = 1
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = int(pkt[IP].proto)
        if TCP in pkt:
            tcp = 1
            sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
            tf = int(pkt[TCP].flags)
            flags["fin"] = 1 if (tf & 0x01) else 0
            flags["syn"] = 1 if (tf & 0x02) else 0
            flags["rst"] = 1 if (tf & 0x04) else 0
            flags["psh"] = 1 if (tf & 0x08) else 0
            flags["ack"] = 1 if (tf & 0x10) else 0
            flags["urg"] = 1 if (tf & 0x20) else 0
            flags["ece"] = 1 if (tf & 0x40) else 0
            flags["cwr"] = 1 if (tf & 0x80) else 0
            fk_tcp = make_flow_key(src, sport, dst, dport)

            # --- MQTT Logic: Check if MQTT layer is present ---
            if MQTT in pkt:
                try:
                    mqtt_type = int(pkt[MQTT].type)
                    mqtt_len = float(pkt[MQTT].len) # Remaining Length

                    # Feature #30: Check Return Code in CONNACK (Type 2)
                    if mqtt_type == 2 and hasattr(pkt[MQTT], 'returncode'):
                        mqtt_rc = int(pkt[MQTT].returncode)

                    # Feature #28: Check Topic Length in PUBLISH (Type 3)
                    if pkt.haslayer(MQTTPublish):
                        topic = pkt[MQTTPublish].topic
                        if topic:
                            mqtt_topic_len = float(len(topic))
                    
                    # Feature #19 & #25: Check Flags in CONNECT (Type 1)
                    if pkt.haslayer(MQTTConnect):
                        if hasattr(pkt[MQTTConnect], 'flags'):
                            fl = pkt[MQTTConnect].flags
                            # Check Clean Session (Bit 1) - Note: Scapy impl dependent, checking attr if obj
                            # If 'flags' is int: CleanSession=0x02, Will=0x04
                            # If 'flags' is object, assume standard attr names
                            try:
                                if hasattr(fl, 'clean_session') and not fl.clean_session:
                                    mqtt_dirty = 1
                                if hasattr(fl, 'will_flag') and fl.will_flag:
                                    mqtt_will = 1
                            except:
                                pass # Fallback if parsing fails
                except Exception:
                    pass # Prevent crash on malformed MQTT
            # --------------------------------------------------

        elif UDP in pkt:
            udp = 1
            sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
            fk_udp = make_flow_key(src, sport, dst, dport)
        elif ICMP in pkt:
            icmp = 1

    http, https, dns, tel, smtp, ssh, irc, dhcp = detect_l7_by_port(sport, dport)
    header_len = compute_header_len(pkt)

    return {
        "ts": float(ts), "size": float(size), "header_len": float(header_len),
        "proto": int(proto),
        "flags": flags, "sport": int(sport), "dport": int(dport),
        "http": http, "https": https, "dns": dns, "tel": tel, "smtp": smtp, "ssh": ssh, "irc": irc, "dhcp": dhcp,
        "tcp": tcp, "udp": udp, "icmp": icmp, "ipv": ipv, "arp": arp, "llc": llc,
        "flow_key_tcp": fk_tcp, "flow_key_udp": fk_udp,
        "src": src, "dst": dst,
        # New MQTT raw fields
        "mqtt_type": mqtt_type,
        "mqtt_len": mqtt_len,
        "mqtt_topic_len": mqtt_topic_len,
        "mqtt_rc": mqtt_rc,
        "mqtt_dirty": mqtt_dirty,
        "mqtt_will": mqtt_will
    }

def update_flows(row):
    ts = row["ts"]; size = int(row["size"])
    if row["flow_key_tcp"]:
        key = row["flow_key_tcp"]
        first_ip, first_port = key[0]
        direction = "fwd" if (row["src"] == first_ip and row["sport"] == first_port) else "bwd"
        fs = tcpflows.get(key)
        if not fs:
            fs = FlowState(ts); tcpflows[key] = fs
        fs.update(ts, direction, size)
    elif row["flow_key_udp"]:
        key = row["flow_key_udp"]
        first_ip, first_port = key[0]
        direction = "fwd" if (row["src"] == first_ip and row["sport"] == first_port) else "bwd"
        fs = udpflows.get(key)
        if not fs:
            fs = FlowState(ts); udpflows[key] = fs
        fs.update(ts, direction, size)

def safe_std(values):
    if len(values) <= 1: return 0.0
    return float(np.std(np.array(values, dtype=float), ddof=1))

def safe_var(values):
    if len(values) <= 1: return 0.0
    return float(np.var(np.array(values, dtype=float), ddof=1))

def summarize_and_send():
    if len(packet_buf) < WINDOW_SIZE: return
    window = list(packet_buf)

    ts_vals = [r["ts"] for r in window]
    duration = (max(ts_vals) - min(ts_vals)) if ts_vals else 0.0
    number = float(len(window))
    sizes = [r["size"] for r in window]
    header_lens = [r["header_len"] for r in window]
    protos = [r["proto"] for r in window if r["proto"] != 0]
    proto_mode = int(Counter(protos).most_common(1)[0][0]) if protos else 0

    def c(name): return sum(r["flags"][name] for r in window)
    fin_count=c("fin"); syn_count=c("syn"); rst_count=c("rst"); psh_count=c("psh")
    ack_count=c("ack"); urg_count=c("urg"); ece_count=c("ece"); cwr_count=c("cwr")
    def frac(x): return (float(x)/number) if number>0 else 0.0

    http = int(any(r["http"] for r in window)); https = int(any(r["https"] for r in window))
    dns = int(any(r["dns"] for r in window)); tel  = int(any(r["tel"] for r in window))
    smtp= int(any(r["smtp"] for r in window)); ssh  = int(any(r["ssh"] for r in window))
    irc = int(any(r["irc"] for r in window))
    tcpf= int(any(r["tcp"] for r in window)); udpf = int(any(r["udp"] for r in window))
    dhcpf=int(any(r["dhcp"] for r in window)); arpf = int(any(r["arp"] for r in window))
    icmpf=int(any(r["icmp"] for r in window)); ipvf = int(any(r["ipv"] for r in window))
    llcf = int(any(r["llc"] for r in window))

    # --- MQTT Flow Feature Aggregation ---
    # 1. Count specific packet types
    mqtt_connect_cnt = float(sum(1 for r in window if r["mqtt_type"] == 1))
    mqtt_publish_cnt = float(sum(1 for r in window if r["mqtt_type"] == 3))
    mqtt_sub_cnt     = float(sum(1 for r in window if r["mqtt_type"] == 8))
    
    # 2. Count Auth Failures (CONNACK with RC != 0)
    mqtt_auth_fail = float(sum(1 for r in window if r["mqtt_type"] == 2 and r["mqtt_rc"] != 0))
    
    # 3. Count Special Flags
    mqtt_dirty_sess = float(sum(r["mqtt_dirty"] for r in window))
    mqtt_will_count = float(sum(r["mqtt_will"] for r in window))
    
    # 4. Average Lengths (Topic & Payload)
    # Filter only relevant packets (len > 0) to avoid dilution by control packets
    payloads = [r["mqtt_len"] for r in window if r["mqtt_len"] > 0]
    mqtt_avg_payload = float(sum(payloads) / len(payloads)) if payloads else 0.0
    
    topics = [r["mqtt_topic_len"] for r in window if r["mqtt_topic_len"] > 0]
    mqtt_avg_topic = float(sum(topics) / len(topics)) if topics else 0.0
    # -------------------------------------

    tot_sum = float(sum(sizes))
    min_len = float(min(sizes)) if sizes else 0.0
    max_len = float(max(sizes)) if sizes else 0.0
    avg_len = float(tot_sum/number) if number>0 else 0.0
    std_len = safe_std(sizes); var_len = safe_var(sizes)

    ts_sorted = sorted(ts_vals)
    iats = [t2 - t1 for t1, t2 in zip(ts_sorted[:-1], ts_sorted[1:])]
    iat_avg = float(sum(iats)/len(iats)) if iats else 0.0

    flow_counter = Counter()
    for r in window:
        if r["flow_key_tcp"]:
            flow_counter[("tcp", r["flow_key_tcp"])] += 1
        if r["flow_key_udp"]:
            flow_counter[("udp", r["flow_key_udp"])] += 1
    dominant = flow_counter.most_common(1)[0][0] if flow_counter else None

    flow_duration = 0.0; srate = 0.0; drate = 0.0
    incoming_sizes=[]; outgoing_sizes=[]
    if dominant:
        tag, key = dominant
        fs = (tcpflows.get(key) if tag=="tcp" else udpflows.get(key))
        if fs:
            flow_duration = float(fs.duration())
            if flow_duration > 0:
                srate = float(fs.fwd_pkts)/flow_duration
                drate = float(fs.bwd_pkts)/flow_duration
        first_ip, first_port = key[0]
        for r in window:
            if r["flow_key_tcp"] == key or r["flow_key_udp"] == key:
                if r["src"] is None: continue
                if (r["src"] == first_ip and r["sport"] == first_port):
                    outgoing_sizes.append(r["size"])
                else:
                    incoming_sizes.append(r["size"])

    magnitue, radius, covariance, weight = dynamic_two_streams(incoming_sizes, outgoing_sizes)
    rate = (number/duration) if duration>0 else 0.0

    record = {
        "flow_duration": float(flow_duration),
        "Header_Length": float(sum(header_lens)/number) if number>0 else 0.0,
        "Protocol Type": float(proto_mode),
        "Duration": float(duration),
        "Rate": float(rate),
        "Srate": float(srate),
        "Drate": float(drate),
        "fin_flag_number": float(frac(fin_count)),
        "syn_flag_number": float(frac(syn_count)),
        "rst_flag_number": float(frac(rst_count)),
        "psh_flag_number": float(frac(psh_count)),
        "ack_flag_number": float(frac(ack_count)),
        "ece_flag_number": float(frac(ece_count)),
        "cwr_flag_number": float(frac(cwr_count)),
        "ack_count": float(ack_count),
        "syn_count": float(syn_count),
        "fin_count": float(fin_count),
        "urg_count": float(urg_count),
        "rst_count": float(rst_count),
        "HTTP": float(http),
        "HTTPS": float(https),
        "DNS": float(dns),
        "Telnet": float(tel),
        "SMTP": float(smtp),
        "SSH": float(ssh),
        "IRC": float(irc),
        "TCP": float(tcpf),
        "UDP": float(udpf),
        "DHCP": float(dhcpf),
        "ARP": float(arpf),
        "ICMP": float(icmpf),
        "IPv": float(ipvf),
        "LLC": float(llcf),
        "Tot sum": float(tot_sum),
        "Min": float(min_len),
        "Max": float(max_len),
        "AVG": float(avg_len),
        "Std": float(std_len),
        "Tot size": float(tot_sum),
        "IAT": float(iat_avg),
        "Number": float(number),
        "Magnitue": float(magnitue),
        "Radius": float(radius),
        "Covariance": float(covariance),
        "Variance": float(var_len),
        "Weight": float(weight),
        # --- MQTT Aggregated Features ---
        "mqtt_connect_count": mqtt_connect_cnt,
        "mqtt_publish_count": mqtt_publish_cnt,
        "mqtt_sub_count": mqtt_sub_cnt,
        "mqtt_auth_fail": mqtt_auth_fail,
        "mqtt_avg_payload": mqtt_avg_payload,
        "mqtt_avg_topic": mqtt_avg_topic,
        "mqtt_dirty_sess": mqtt_dirty_sess,
        "mqtt_will_count": mqtt_will_count
        # --------------------------------
    }

    try:
        resp = requests.post(ML_URL, json={"flows":[record]}, timeout=CONNECT_TIMEOUT)
        if resp.status_code != 200:
            print(f"[sender] HTTP {resp.status_code}: {resp.text[:160]}")
    except requests.RequestException as e:
        print(f"[sender] POST error: {e}")

def on_packet(pkt):
    ts = time.time()
    try:
        row = packet_to_row(pkt, ts)
        packet_buf.append(row)
        update_flows(row)
        if len(packet_buf) == WINDOW_SIZE:
            summarize_and_send()
            packet_buf.clear()
    except Exception as e:
        print(f"[sniffer] packet error: {e}")

def main():
    # Bind 1883 to MQTT so Scapy parses the payload
    bind_layers(TCP, MQTT, sport=1883)
    bind_layers(TCP, MQTT, dport=1883)
    
    print(f"[i] Sniffing on {INTERFACE} (window={WINDOW_SIZE}) -> {ML_URL}")
    sniff(iface=INTERFACE, filter="ip or arp", prn=on_packet, store=False)

if __name__ == "__main__":
    main()