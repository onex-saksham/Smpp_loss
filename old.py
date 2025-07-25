import pyshark
import pandas as pd
import struct
from datetime import datetime
import os
import glob
import sys
import asyncio
import logging
import re
 
logger = logging.getLogger(__name__)
 
# Configure TShark path
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'
 
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('smpp_analysis.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()
 
logger = setup_logging()
 
def clean_payload(raw):
    if isinstance(raw, list):
        raw = ''.join(raw)
    return raw.replace(':', '').replace(' ', '').strip()
 
def extract_pdus(payload_hex):
    pdus = []
    try:
        payload = bytes.fromhex(payload_hex)
        i = 0
        while i + 4 <= len(payload):
            length = struct.unpack('!I', payload[i:i+4])[0]
            if length < 16 or i + length > len(payload):
                break
            pdus.append(payload[i:i+length])
            i += length
    except Exception as e:
        logger.warning(f"PDU extraction error: {e}")
    return pdus

def parse_pdu(pdu_bytes, pkt_info):
    if len(pdu_bytes) < 16:
        return None
 
    # common header
    cmd = f"0x{struct.unpack('!I', pdu_bytes[4:8])[0]:08x}"
    seq = str(struct.unpack('!I', pdu_bytes[12:16])[0])
 
    # prepare outputs
    msg_id = None
    source_addr = None
    destination_addr = None
    short_message = None
 
    try:
        # Submit_SM_Resp → simple null‑terminated msg_id
        if cmd == '0x80000004':
            null_pos = pdu_bytes.find(b'\x00', 16)
            if null_pos != -1:
                msg_id = pdu_bytes[16:null_pos].decode('utf-8', 'ignore').strip().lower()
 
        # Deliver_SM → byte‑by‑byte parse per SMPP spec
        elif cmd == '0x00000005':
            body = pdu_bytes[16:]
            off = 0
 
            # 1) skip service_type C‑string
            off = body.find(b'\x00', off) + 1
 
            # 2) skip source_addr_ton + source_addr_npi
            off += 2
 
            # 3) read source_addr (C‑string = MSISDN)
            end = body.find(b'\x00', off)
            source_addr = body[off:end].decode('ascii', 'ignore')
            off = end + 1
 
            # 4) skip dest_addr_ton + dest_addr_npi
            off += 2
 
            # 5) read destination_addr (C‑string = alphanumeric)
            end = body.find(b'\x00', off)
            destination_addr = body[off:end].decode('ascii', 'ignore')
            off = end + 1
 
            # 6) skip esm_class, protocol_id, priority_flag
            off += 3
 
            # 7) skip schedule_delivery_time C‑string
            off = body.find(b'\x00', off) + 1
 
            # 8) skip validity_period C‑string
            off = body.find(b'\x00', off) + 1
 
            # 9) skip registered_delivery, replace_if_present_flag,
            #    data_coding, sm_default_msg_id (4 bytes)
            off += 4
 
            # 10) read short_message: length byte + message bytes
            sm_len = body[off]
            off += 1
            short_message = body[off:off + sm_len].decode('utf-8', 'ignore')
 
            # Extract delivery receipt's internal ID
            if short_message:
                m = re.search(r'id:([^\s;]+)', short_message, re.IGNORECASE)
                if m:
                    msg_id = m.group(1).strip().lower()
 
    except Exception as e:
        logger.error(f"PDU parsing error (cmd={cmd}): {e}")
 
    return {
        'command_id':       cmd,
        'sequence_number':  seq,
        'message_id':       msg_id,
        'originator_addr': source_addr,  # Changed from source_addr
        'recipient_addr':  destination_addr,  # Changed from destination_addr
        'short_message':    short_message,
        'src_ip':           pkt_info['src_ip'],
        'src_port':         pkt_info['src_port'],
        'dst_ip':           pkt_info['dst_ip'],
        'dst_port':         pkt_info['dst_port'],
        'timestamp':        pkt_info['timestamp']
    }
 
def main():
    # Directory handling
    dir_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap_files = sorted([f for f in glob.glob(os.path.join(dir_path, '*.pcap*')) if os.path.isfile(f)])
    
    if not pcap_files:
        logger.error(f"No PCAP files found in {dir_path}")
        sys.exit(1)
 
    # Data structures
    submit_sm = {}
    submit_sm_resp = {}
    deliver_sm = {}
    deliver_sm_resp = {}
    msgid_to_deliver = {}
    all_records = []
    chain_records = []
 
    counters = {
        'submit_sm': 0,
        'submit_sm_resp': 0,
        'deliver_sm': 0,
        'deliver_sm_resp': 0,
        'submit_resp_matched': 0,
        'resp_deliver_matched': 0,
        'deliver_resp_matched': 0,
        'full_chains': 0
    }
 
    # Process each PCAP
    for file in pcap_files:
        logger.info(f"Processing: {file}")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            cap = pyshark.FileCapture(
                file,
                display_filter="smpp",
                use_json=True,
                include_raw=True,
                keep_packets=False
            )
            
            for pkt in cap:
                try:
                    raw_payload = getattr(pkt.tcp, 'segment_data', None) or getattr(pkt.tcp, 'payload', None)
                    if not raw_payload:
                        continue
                        
                    payload_hex = clean_payload(raw_payload)
                    if not payload_hex:
                        continue
 
                    pkt_info = {
                        'src_ip': pkt.ip.src,
                        'dst_ip': pkt.ip.dst,
                        'src_port': pkt.tcp.srcport,
                        'dst_port': pkt.tcp.dstport,
                        'timestamp': datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime('%d/%m/%y %H:%M:%S')
                    }
 
                    for pdu in extract_pdus(payload_hex):
                        rec = parse_pdu(pdu, pkt_info)
                        if not rec:
                            continue
                            
                        all_records.append(rec)
                        key = (rec['sequence_number'], rec['src_ip'], rec['src_port'], rec['dst_ip'], rec['dst_port'])
                        
                        if rec['command_id'] == '0x00000004':
                            submit_sm[key] = rec
                            counters['submit_sm'] += 1
                        elif rec['command_id'] == '0x80000004':
                            submit_sm_resp[key] = rec
                            counters['submit_sm_resp'] += 1
                        elif rec['command_id'] == '0x00000005':
                            deliver_sm[key] = rec
                            if rec['message_id']:
                                msgid_to_deliver.setdefault(rec['message_id'], []).append((key, rec))
                            counters['deliver_sm'] += 1
                        elif rec['command_id'] == '0x80000005':
                            deliver_sm_resp[key] = rec
                            counters['deliver_sm_resp'] += 1
                            
                except Exception as e:
                    logger.warning(f"Packet error: {e}")
                    
            cap.close()
            loop.close()
            
        except Exception as e:
            logger.error(f"File error: {e}")
 
    # Enhanced matching logic
    logger.info("\nMatching Debug:")
    logger.info(f"Submit_SM_Resp IDs: {len(submit_sm_resp)}")
    logger.info(f"Deliver_SM IDs: {len(msgid_to_deliver)}")
    
    for sub_key, sub in submit_sm.items():
        rev_key = (sub_key[0], sub_key[3], sub_key[4], sub_key[1], sub_key[2])
        resp = submit_sm_resp.get(rev_key)
        mid = None
        dkey = None
        drec = None
        dresp = None
        
        if resp:
            counters['submit_resp_matched'] += 1
            mid = resp['message_id']
            
            if mid and mid in msgid_to_deliver:
                # Find all deliver_sm with matching message_id
                possible_deliveries = msgid_to_deliver[mid]
                
                # First try to find deliver_sm with matching IPs (regardless of ports)
                for dk, dr in possible_deliveries:
                    if (dk[1] == rev_key[3] and dk[3] == rev_key[1]):  # Reverse IP direction
                        logger.info(f"Found potential deliver_sm match for MID {mid}")
                        dkey = dk
                        drec = dr
                        
                        # Verify the deliver_sm contains the expected source/dest addresses
                        if drec['originator_addr'] and drec['recipient_addr']:
                            logger.info(f"Confirmed deliver_sm match with addresses: {drec['originator_addr']} -> {drec['recipient_addr']}")
                            counters['resp_deliver_matched'] += 1
                            
                            # Look for deliver_sm_resp
                            dr_key = (dk[0], dk[3], dk[4], dk[1], dk[2])
                            dresp = deliver_sm_resp.get(dr_key)
                            if dresp:
                                logger.info(f"Found complete chain for MID {mid}")
                                counters['deliver_resp_matched'] += 1
                                counters['full_chains'] += 1
                            break
                
                # If no match found with IPs, try any deliver_sm with matching message_id
                if not dkey and possible_deliveries:
                    dkey, drec = possible_deliveries[0]
                    logger.warning(f"Using first deliver_sm for MID {mid} without IP verification")
                    counters['resp_deliver_matched'] += 1
                    
                    # Look for deliver_sm_resp
                    dr_key = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
                    dresp = deliver_sm_resp.get(dr_key)
                    if dresp:
                        counters['deliver_resp_matched'] += 1
                        counters['full_chains'] += 1
 
        # Add to chain records with full port information
        chain_records.append({
            'submit_sm_seq': sub_key[0],
            'submit_time': sub['timestamp'],
            'submit_src': f"{sub['src_ip']}:{sub['src_port']}",
            'submit_dst': f"{sub['dst_ip']}:{sub['dst_port']}",
            'submit_resp_seq': resp['sequence_number'] if resp else '',
            'submit_resp_time': resp['timestamp'] if resp else '',
            'submit_resp_src': f"{resp['src_ip']}:{resp['src_port']}" if resp else '',
            'submit_resp_dst': f"{resp['dst_ip']}:{resp['dst_port']}" if resp else '',
            'message_id': mid or '',
            'originator_addr': drec['originator_addr'] if drec else '',  # Changed from source_addr
            'recipient_addr': drec['recipient_addr'] if drec else '',  # Changed from destination_addr
            'message_content': drec['short_message'] if drec else '',
            'deliver_seq': dkey[0] if dkey else '',
            'deliver_time': drec['timestamp'] if drec else '',
            'deliver_src': f"{drec['src_ip']}:{drec['src_port']}" if drec else '',
            'deliver_dst': f"{drec['dst_ip']}:{drec['dst_port']}" if drec else '',
            'deliver_resp_seq': dresp['sequence_number'] if dresp else '',
            'deliver_resp_time': dresp['timestamp'] if dresp else '',
            'deliver_resp_src': f"{dresp['src_ip']}:{dresp['src_port']}" if dresp else '',
            'deliver_resp_dst': f"{dresp['dst_ip']}:{dresp['dst_port']}" if dresp else ''
        })
 
    # Save results
    pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
    pd.DataFrame(chain_records).to_csv("smpp_full_chains.csv", index=False)
    pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)
 
    logger.info("\nFinal Counters:")
    for k, v in counters.items():
        logger.info(f"{k}: {v}")
 
if __name__ == "__main__":
    main()
 