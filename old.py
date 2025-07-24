import pandas as pd
import struct
from datetime import datetime
import os
import glob
import sys
import pyshark
 
# Configuration
if len(sys.argv) > 1:
    dir_path = sys.argv[1]
else:
    dir_path = '.'  # current directory
 
pcap_files = sorted(glob.glob(os.path.join(dir_path, '*.pcap*')))
if not pcap_files:
    print(f"⚠️ No PCAP files found in directory: {dir_path}")
    sys.exit(1)
 
fmt = '%d/%m/%y %H:%M:%S'
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'
 
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
    'full_chains': 0,
    'partial_chains': 0,
    'submit_resp_matched': 0,
    'resp_deliver_matched': 0,
    'deliver_resp_matched': 0
}
 
def clean_payload(raw_payload):
    try:
        if isinstance(raw_payload, list):
            raw_payload = ''.join(raw_payload)
        return raw_payload.replace(':', '').replace(' ', '').strip()
    except:
        return None
 
def extract_pdus_from_payload(payload_hex):
    pdus = []
    try:
        payload = bytes.fromhex(payload_hex)
        i = 0
        while i + 4 <= len(payload):
            pdu_len = struct.unpack('!I', payload[i:i+4])[0]
            if pdu_len < 16 or i + pdu_len > len(payload):
                break
            pdus.append(payload[i:i+pdu_len])
            i += pdu_len
    except:
        pass
    return pdus
 
def parse_single_pdu(pdu_bytes, pkt_info):
    try:
        if len(pdu_bytes) < 16:
            return None
        
        cmd = f"0x{struct.unpack('!I', pdu_bytes[4:8])[0]:08x}"
        if cmd in ('0x00000015', '0x80000015'):
            return None
            
        seq = str(struct.unpack('!I', pdu_bytes[12:16])[0])
        msg_id = None
        origin_addr = None
        recipient_addr = None
        dlvrd_status = None
        submit_date = None
        done_date = None
        status = None
        error_code = None
        text = None
 
        # Extract addresses from all PDU types
        try:
            body_start = 16
            # Origin address (source_addr)
            null_pos = pdu_bytes.find(b'\x00', body_start)
            origin_addr = pdu_bytes[body_start:null_pos].decode('ascii', errors='ignore') if null_pos != -1 else None
            
            # Recipient address (destination_addr)
            next_pos = null_pos + 1
            null_pos = pdu_bytes.find(b'\x00', next_pos)
            recipient_addr = pdu_bytes[next_pos:null_pos].decode('ascii', errors='ignore') if null_pos != -1 else None
        except:
            pass
 
        if cmd == '0x00000005':  # deliver_sm
            # Extract message ID from hex
            sm_hex = pdu_bytes.hex()
            start = sm_hex.find("69643a")  # 'id:'
            end = sm_hex.find("737562")    # 'sub'
            if start != -1 and end > start:
                try:
                    msg_id_hex = sm_hex[start+6:end]
                    msg_id = bytes.fromhex(msg_id_hex).decode('utf-8', errors='ignore').strip().lower()
                except:
                    pass
 
            # Enhanced delivery report parsing
            try:
                body = pdu_bytes[16:].decode('ascii', errors='ignore')
                if 'id:' in body:
                    # Parse delivery report fields
                    parts = [p.strip() for p in body.split() if p.strip()]
                    for part in parts:
                        if part.startswith('id:'):
                            msg_id = part[3:]
                        elif part.startswith('sub:'):
                            dlvrd_status = part[4:]
                        elif part.startswith('dlvrd:'):
                            dlvrd_status = part[6:]
                        elif part.startswith('submitdate:'):
                            submit_date = part[11:]
                        elif part.startswith('donedate:'):
                            done_date = part[9:]
                        elif part.startswith('stat:'):
                            status = part[5:]
                        elif part.startswith('err:'):
                            error_code = part[4:]
                        elif part.startswith('text:'):
                            text = part[5:]
            except Exception as e:
                print(f"Delivery report parsing error: {e}")
 
        elif cmd == '0x80000004':  # submit_sm_resp
            try:
                parts = pdu_bytes[16:].split(b'\x00')
                if parts:
                    msg_id = parts[0].decode('utf-8', errors='ignore').strip().lower()
            except:
                pass
 
        return {
            'command_id': cmd,
            'sequence_number': seq,
            'message_id': msg_id,
            'src_ip': pkt_info['src_ip'],
            'src_port': pkt_info['src_port'],
            'dst_ip': pkt_info['dst_ip'],
            'dst_port': pkt_info['dst_port'],
            'timestamp': pkt_info['timestamp'],
            'origin_addr': origin_addr,
            'recipient_addr': recipient_addr,
            'dlvrd_status': dlvrd_status,
            'submit_date': submit_date,
            'done_date': done_date,
            'status': status,
            'error_code': error_code,
            'message_text': text
        }
    except Exception as e:
        print(f"PDU parsing error: {e}")
        return None
 
# Packet processing
for pcap_file in pcap_files:
    if not os.path.exists(pcap_file):
        print(f"⚠️ File not found: {pcap_file}")
        continue
 
    print(f"🔍 Parsing {pcap_file}")
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="smpp", use_json=True, include_raw=True, keep_packets=False)
 
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
                    'timestamp': datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime(fmt)
                }
 
                for pdu in extract_pdus_from_payload(payload_hex):
                    rec = parse_single_pdu(pdu, pkt_info)
                    if not rec:
                        continue
 
                    all_records.append(rec)
                    key = (rec['sequence_number'], rec['src_ip'], rec['src_port'], rec['dst_ip'], rec['dst_port'])
                    cmd = rec['command_id']
                    mid = rec['message_id']
 
                    if cmd == '0x00000004':
                        submit_sm[key] = rec
                        counters['submit_sm'] += 1
                    elif cmd == '0x80000004':
                        submit_sm_resp[key] = rec
                        counters['submit_sm_resp'] += 1
                    elif cmd == '0x00000005':
                        deliver_sm[key] = rec
                        if mid:
                            msgid_to_deliver.setdefault(mid, []).append((key, rec))
                        counters['deliver_sm'] += 1
                    elif cmd == '0x80000005':
                        deliver_sm_resp[key] = rec
                        counters['deliver_sm_resp'] += 1
 
            except Exception as e:
                print(f"⚠️ Packet error: {e}")
        cap.close()
    except Exception as e:
        print(f"❌ Failed to process {pcap_file}: {e}")
 
# Matching logic
# 🧩 Build chain records - Optimized but preserves original matching
chain_records = []
 
# 1. First build msgid_map exactly as before (your original matching logic)
msgid_map = {}
submit_sms = {}
deliver_sms = {}
 
for rec in all_records:
    cmd = rec['command_id']
    seq = rec['sequence_number']
    src_ip = rec['src_ip']
    src_port = rec['src_port']
    dst_ip = rec['dst_ip']
    dst_port = rec['dst_port']
    msg_id = rec['message_id']
    
    key = (seq, src_ip, src_port, dst_ip, dst_port)
    
    if cmd == '0x00000004':  # Submit_SM
        submit_sms[key] = rec
        
    elif cmd == '0x80000004':  # Submit_SM_Resp
        rev_key = (seq, dst_ip, dst_port, src_ip, src_port)
        if rev_key in submit_sms:
            if msg_id:
                if msg_id not in msgid_map:
                    msgid_map[msg_id] = {
                        'Submit_SM': None,
                        'Submit_SM_Resp': None,
                        'Deliver_SM': None,
                        'Deliver_SM_Resp': None
                    }
                msgid_map[msg_id]['Submit_SM'] = submit_sms[rev_key]
                msgid_map[msg_id]['Submit_SM_Resp'] = rec
    
    elif cmd == '0x00000005':  # Deliver_SM
        deliver_sms[key] = rec
        if msg_id and msg_id in msgid_map:
            msgid_map[msg_id]['Deliver_SM'] = rec
    
    elif cmd == '0x80000005':  # Deliver_SM_Resp
        rev_key = (seq, dst_ip, dst_port, src_ip, src_port)
        if rev_key in deliver_sms:
            deliver_rec = deliver_sms[rev_key]
            d_msg_id = deliver_rec.get('message_id')
            if d_msg_id and d_msg_id in msgid_map:
                msgid_map[d_msg_id]['Deliver_SM_Resp'] = rec
 
# 2. Build chains with all message IDs (optimized)
msg_id_to_records = {}
for rec in all_records:
    if rec['message_id']:
        if rec['message_id'] not in msg_id_to_records:
            msg_id_to_records[rec['message_id']] = []
        msg_id_to_records[rec['message_id']].append(rec)
 
for msg_id, records in msg_id_to_records.items():
    chain = {
        'message_id': msg_id,
        'submit_sm_seq': None, 'submit_sm_time': None,
        'submit_src': None, 'submit_dst': None,
        'submit_resp_seq': None, 'submit_resp_time': None,
        'deliver_seq': None, 'deliver_time': None,
        'deliver_src': None, 'deliver_dst': None,
        'deliver_resp_seq': None, 'deliver_resp_time': None,
        'origin_addr': None, 'recipient_addr': None,
        'dlvrd_status': None, 'submit_date': None,
        'done_date': None, 'status': None,
        'error_code': None, 'message_text': None
    }
    
    # Use matched chains if available
    if msg_id in msgid_map:
        parts = msgid_map[msg_id]
        if parts['Submit_SM']:
            s = parts['Submit_SM']
            chain.update({
                'submit_sm_seq': s['sequence_number'],
                'submit_sm_time': s['timestamp'],
                'submit_src': f"{s['src_ip']}:{s['src_port']}",
                'submit_dst': f"{s['dst_ip']}:{s['dst_port']}",
                'origin_addr': s.get('origin_addr'),
                'recipient_addr': s.get('recipient_addr')
            })
        
        if parts['Submit_SM_Resp']:
            sr = parts['Submit_SM_Resp']
            chain.update({
                'submit_resp_seq': sr['sequence_number'],
                'submit_resp_time': sr['timestamp']
            })
            
        if parts['Deliver_SM']:
            d = parts['Deliver_SM']
            chain.update({
                'deliver_seq': d['sequence_number'],
                'deliver_time': d['timestamp'],
                'deliver_src': f"{d['src_ip']}:{d['src_port']}",
                'deliver_dst': f"{d['dst_ip']}:{d['dst_port']}",
                'dlvrd_status': d.get('dlvrd_status'),
                'submit_date': d.get('submit_date'),
                'done_date': d.get('done_date'),
                'status': d.get('status'),
                'error_code': d.get('error_code'),
                'message_text': d.get('message_text')
            })
            
        if parts['Deliver_SM_Resp']:
            dr = parts['Deliver_SM_Resp']
            chain.update({
                'deliver_resp_seq': dr['sequence_number'],
                'deliver_resp_time': dr['timestamp']
            })
    
    # Fallback to individual records (only if not fully matched)
    for rec in records:
        cmd = rec['command_id']
        if cmd == '0x00000004' and not chain['submit_sm_seq']:
            chain.update({
                'submit_sm_seq': rec['sequence_number'],
                'submit_sm_time': rec['timestamp'],
                'submit_src': f"{rec['src_ip']}:{rec['src_port']}",
                'submit_dst': f"{rec['dst_ip']}:{rec['dst_port']}",
                'origin_addr': rec.get('origin_addr'),
                'recipient_addr': rec.get('recipient_addr')
            })
        elif cmd == '0x80000004' and not chain['submit_resp_seq']:
            chain.update({
                'submit_resp_seq': rec['sequence_number'],
                'submit_resp_time': rec['timestamp']
            })
        elif cmd == '0x00000005' and not chain['deliver_seq']:
            chain.update({
                'deliver_seq': rec['sequence_number'],
                'deliver_time': rec['timestamp'],
                'deliver_src': f"{rec['src_ip']}:{rec['src_port']}",
                'deliver_dst': f"{rec['dst_ip']}:{rec['dst_port']}",
                'dlvrd_status': rec.get('dlvrd_status'),
                'submit_date': rec.get('submit_date'),
                'done_date': rec.get('done_date'),
                'status': rec.get('status'),
                'error_code': rec.get('error_code'),
                'message_text': rec.get('message_text')
            })
        elif cmd == '0x80000005' and not chain['deliver_resp_seq']:
            chain.update({
                'deliver_resp_seq': rec['sequence_number'],
                'deliver_resp_time': rec['timestamp']
            })
    
    chain_records.append(chain)
 
# Update counters (original logic)
counters['full_chains'] = sum(1 for c in chain_records if all([
    c['submit_sm_seq'], c['submit_resp_seq'],
    c['deliver_seq'], c['deliver_resp_seq']
]))
counters['partial_chains'] = len(chain_records) - counters['full_chains']
 
# Save outputs
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(chain_records).to_csv("smpp_full_chains.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)
 
# Summary
print("\n✅ Completed parsing and matching. Summary:")
for k, v in counters.items():
    print(f"  {k}: {v}")