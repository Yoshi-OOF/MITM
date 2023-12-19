import logging
import json
from scapy.all import *

with open('config.json', 'r') as config_file:
   config = json.load(config_file)

class NetworkLogger:
   def __init__(self, log_file):
      self.log_file = log_file
      logging.basicConfig(filename=self.log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
   
   def log_network_activity(self, packet):
      if IP in packet:
         src_ip = packet[IP].src
         dst_ip = packet[IP].dst

         if DNSQR in packet:
            logging.info("From " + src_ip + " to " + dst_ip + " containing " + packet.summary() + " and querying " + packet[DNSQR].qname.decode())
            log_entry = {'src_ip': src_ip, 'dst_ip': dst_ip, 'packet_summary': packet.summary(), 'dns_query': packet[DNSQR].qname.decode()}
         else:
            logging.info("From " + src_ip + " to " + dst_ip + " containing " + packet.summary())
            log_entry = {'src_ip': src_ip, 'dst_ip': dst_ip, 'packet_summary': packet.summary()}

         with open('network_activity.json', 'a') as log_file:
            json.dump(log_entry, log_file)
   
network_logger = NetworkLogger(config['log_file'])
sniff(prn=network_logger.log_network_activity, store=0)