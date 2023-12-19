import scapy.all as scapy
from scapy.layers import http
import json
import datetime
import network_logger

with open('config.json', 'r') as config_file:
   config = json.load(config_file)

network_logger = network_logger.NetworkLogger(config['log_file'])

def mitm_attack():
   def process_packet(packet):
      if packet.haslayer(http.HTTPRequest):
         url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
         method = packet[http.HTTPRequest].Method.decode()
         timestamp = str(datetime.datetime.now())
         log_entry = {'url': url, 'method': method, 'timestamp': timestamp}
         network_logger.log(log_entry)
         scapy.sniff(iface=config['interface'], store=False, prn=process_packet)


if __name__ == "__main__":
   mitm_attack()
   