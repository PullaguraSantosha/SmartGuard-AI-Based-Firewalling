import time
import threading
import json
import os
import subprocess
import re
from scapy.all import sniff, IP, UDP, ICMP, TCP
from collections import defaultdict, deque
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPRegressor
from sklearn.linear_model import LinearRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PolynomialFeatures
import warnings
warnings.filterwarnings('ignore')

# ========== JSON Storage Configuration ==========
ATTACK_DATA_PATH = "/tmp/attack_data.json"
UDP_FEATURES_PATH = "/tmp/udp_features.json"
ICMP_FEATURES_PATH = "/tmp/icmp_features.json"
SYN_FEATURES_PATH = "/tmp/syn_features.json"
FIREWALL_ACTION_PATH = "/tmp/fwaction.json"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ========== ML Model Paths ==========
UDP_MODEL_PATH = os.path.join(SCRIPT_DIR, "udp_flood_model.pkl")
UDP_SCALER_PATH = os.path.join(SCRIPT_DIR, "udp_flood_scaler.pkl")
UDP_BACKUP_MODEL_PATH = os.path.join(SCRIPT_DIR, "backup_udp_flood_model.pkl")

# ICMP Models
ICMP_MODEL_PATH = os.path.join(SCRIPT_DIR, "icmp_flood_model.pkl")
ICMP_SCALER_PATH = os.path.join(SCRIPT_DIR, "icmp_flood_scaler.pkl")
ICMP_BACKUP_MODEL_PATH = os.path.join(SCRIPT_DIR, "backup_icmp_flood_model.pkl")

# SYN Models
SYN_MODEL_PATH = os.path.join(SCRIPT_DIR, "syn_flood_model.pkl")
SYN_SCALER_PATH = os.path.join(SCRIPT_DIR, "syn_flood_scaler.pkl")
SYN_BACKUP_MODEL_PATH = os.path.join(SCRIPT_DIR, "backup_syn_flood_model.pkl")
SYN_CONFIDENCE_NORMALIZER_PATH = os.path.join(SCRIPT_DIR, "syn_normalization.pkl")

# ========== Global Variables ==========
# UDP Detection
udp_packet_times = deque()
udp_dst_port_counter = defaultdict(int)
udp_src_ip_counter = defaultdict(int)
udp_packet_sizes = deque()
udp_inter_arrival_times = deque()
udp_large_payload_count = 0
udp_last_packet_time = 0

# ICMP Detection
icmp_packet_times = deque()
icmp_source_ips = defaultdict(set)
icmp_payload_sizes = []

# SYN Detection
syn_packet_times = deque()
syn_source_ports = deque()  # Change to simple deque for source ports
syn_dest_ports = deque()    # Add destination ports tracking
syn_packet_sizes = []

# Detection flags and states
udp_flood_pps_variant = 0
udp_flood_large_payload_variant = 0
udp_flood_port_variation_variant = 0
udp_ml_detection_flag = 0
udp_attack_active = False
udp_last_attack_time = 0

icmp_flood_pps_variant = 0
icmp_flood_large_payload_variant = 0
icmp_flood_spoofed_ips_variant = 0
icmp_ml_detection_flag = 0
icmp_attack_active = False
icmp_last_attack_time = 0

syn_flood_pps_variant = 0
syn_flood_port_variant = 0
syn_flood_size_variant = 0
syn_ml_detection_flag = 0
syn_attack_active = False
syn_last_attack_time = 0

# Traffic state tracking
udp_normal_periods = 0
icmp_normal_periods = 0
syn_normal_periods = 0
NORMAL_THRESHOLD_PERIODS = 3  # Number of consecutive normal periods to declare "all clear"

last_seen_counts = {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
session_dropped_packets = {
    "udp": 0,
    "icmp": 0, 
    "tcp": 0,
    "total": 0
}

# Global cumulative dropped packet counters (never reset)
global_dropped_packets = {
    "udp": 0,
    "icmp": 0,
    "tcp": 0,
    "total": 0
}
global_counter_lock = threading.Lock()
counters_reset_flag = False
# Dropped packet counters
# Current firewall state
current_fw_action = "none"

# ========== Thresholds ==========
WINDOW_SIZE = 5

# Minimum thresholds for considering traffic as "active"
MIN_TRAFFIC_THRESHOLD = 1.0  # Minimum PPS to consider as active traffic

# UDP Thresholds
UDP_RATE_THRESHOLD = 800
UDP_LARGE_PAYLOAD_THRESHOLD = 1000
UDP_PORT_VARIATION_THRESHOLD = 50

# ICMP Thresholds
ICMP_PPS_THRESHOLD = 1000
ICMP_UNIQUE_IP_THRESHOLD = 150
ICMP_LARGE_PAYLOAD_THRESHOLD = 1400

# SYN Thresholds
SYN_PPS_THRESHOLD = 1000
SYN_UNIQUE_SPORT_THRESHOLD = 500
SYN_AVG_PKT_SIZE_THRESHOLD = 100

# PPS Weight Configuration (for ICMP and UDP)
PPS_WEIGHT_MULTIPLIER = 1.2
PPS_CONFIDENCE_BOOST = 15
MULTI_FEATURE_REDUCTION = 0.1
THREE_FEATURE_REDUCTION = 0.2

# Port Randomization Enhancement (for UDP)
PORT_WEIGHT_MULTIPLIER = 1.4  # Increased weight for port randomization
PORT_CONFIDENCE_BOOST = 20     # Higher confidence boost for port attacks

# ========== Locks ==========
udp_lock = threading.Lock()
icmp_lock = threading.Lock()
syn_lock = threading.Lock()
json_lock = threading.Lock()
firewall_lock = threading.Lock()

# ========== ML Components ==========
# UDP ML Components
udp_ml_model = None
udp_backup_model = None
udp_ml_scaler = None
udp_ml_enabled = False

# ICMP ML Components
icmp_ml_model = None
icmp_backup_model = None
icmp_ml_scaler = None
icmp_ml_enabled = False

# SYN ML Components
syn_ml_model = None
syn_backup_model = None
syn_ml_scaler = None
syn_confidence_normalizer = None
syn_ml_enabled = False
syn_normalizer_enabled = False

# Global variables for rate limiting
packet_timestamps = deque()
RATE_LIMIT = 800  # packets per second

#global pkt
current_pkt = None

# ========== Firewall Management Functions ==========
def run_iptables_command(command):
    """Execute iptables command and return success status"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"❌ iptables command failed: {command}")
            print(f"Error: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"❌ iptables command timed out: {command}")
        return False
    except Exception as e:
        print(f"❌ Error executing iptables command: {e}")
        return False

def flush_forward_rules():
    """Flush all FORWARD chain rules and properly handle counter transitions"""
    global last_seen_counts, session_dropped_packets
    
    print("🔄 Flushing FORWARD chain rules...")
    
    # Capture final session counts before flush
    with global_counter_lock:
        final_session_counts = get_dropped_packet_counts()
        
        # Add final session counts to global totals
        global_dropped_packets["udp"] += final_session_counts["udp"]
        global_dropped_packets["icmp"] += final_session_counts["icmp"] 
        global_dropped_packets["tcp"] += final_session_counts["tcp"]
        global_dropped_packets["total"] = (global_dropped_packets["udp"] + 
                                         global_dropped_packets["icmp"] + 
                                         global_dropped_packets["tcp"])
        
        # Store the final session totals before reset
        session_dropped_packets = final_session_counts.copy()
    
    # Actually flush the rules
    result = run_iptables_command("iptables-legacy -F FORWARD")
    
    # Reset tracking for new session after flush
    with global_counter_lock:
        last_seen_counts = {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
        # Note: session_dropped_packets keeps the final values from before flush
    
    return result

def get_current_session_counts():
    """Get current session dropped packet counts (since last flush)"""
    return get_dropped_packet_counts()

def get_global_cumulative_counts():
    """Get global cumulative dropped packet counts (all time)"""
    with global_counter_lock:
        current_session = get_dropped_packet_counts()
        
        # Calculate total global counts (previous sessions + current session)
        total_global = {
            "udp": global_dropped_packets["udp"] + current_session["udp"],
            "icmp": global_dropped_packets["icmp"] + current_session["icmp"], 
            "tcp": global_dropped_packets["tcp"] + current_session["tcp"]
        }
        total_global["total"] = total_global["udp"] + total_global["icmp"] + total_global["tcp"]
        
        return total_global

def update_global_dropped_counters():
    """Update global dropped packet counters with proper session/global separation"""
    global global_dropped_packets, last_seen_counts
    
    with global_counter_lock:
        current_counts = get_dropped_packet_counts()
        
        # Handle counter resets (when current < last_seen, rules were flushed)
        # This should rarely happen now since flush_forward_rules() handles it properly
        if (current_counts["udp"] < last_seen_counts["udp"] or 
            current_counts["icmp"] < last_seen_counts["icmp"] or 
            current_counts["tcp"] < last_seen_counts["tcp"]):
            
            print("⚠️ Unexpected counter reset detected - adjusting...")
            # Add the lost counts from before the reset
            global_dropped_packets["udp"] += last_seen_counts["udp"]
            global_dropped_packets["icmp"] += last_seen_counts["icmp"]
            global_dropped_packets["tcp"] += last_seen_counts["tcp"]
            
            # Reset tracking to start fresh
            last_seen_counts = {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
        
        # Update last seen counts for next iteration
        last_seen_counts = current_counts.copy()
        
        # Recalculate global totals
        global_dropped_packets["total"] = (global_dropped_packets["udp"] + 
                                         global_dropped_packets["icmp"] + 
                                         global_dropped_packets["tcp"])
        
        return {
            "session": current_counts.copy(),
            "global_cumulative": get_global_cumulative_counts()
        }


def set_forward_policy(policy):
    """Set FORWARD chain policy (ACCEPT or DROP)"""
    print(f"📋 Setting FORWARD policy to {policy}...")
    return run_iptables_command(f"iptables-legacy -P FORWARD {policy}")

def apply_block_rules():
    """Apply blocking rules for all monitored protocols"""
    print("🚫 Applying protocol blocking rules...")
    commands = [
        "iptables-legacy -A FORWARD -p icmp -j DROP",
        "iptables-legacy -A FORWARD -p udp -j DROP", 
        "iptables-legacy -A FORWARD -p tcp --syn -j DROP"
    ]
    
    success = True
    for cmd in commands:
        if not run_iptables_command(cmd):
            success = False
    
    return success

def apply_rate_limit_rules():
    """Apply rate limiting rules"""
    print("⏱️ Applying rate limiting rules...")
    commands = [
        "iptables-legacy -I FORWARD 1 -m limit --limit 100/sec --limit-burst 20 -j ACCEPT",
        "iptables-legacy -A FORWARD -p icmp -j DROP",
        "iptables-legacy -A FORWARD -p udp -j DROP",
        "iptables-legacy -A FORWARD -p tcp -j DROP"
    ]
    
    success = True
    for cmd in commands:
        if not run_iptables_command(cmd):
            success = False
    
    return success

def allow_all_traffic():
    """Allow all traffic through FORWARD chain"""
    print("✅ Allowing all traffic...")
    flush_forward_rules()
    return set_forward_policy("ACCEPT")

def get_dropped_packet_counts():
    """Get dropped packet counts from iptables statistics with proper K/M suffix handling"""
    try:
        result = subprocess.run("iptables-legacy -L FORWARD -v -n --line-numbers", 
                              shell=True, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print("❌ Failed to get iptables statistics")
            return {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
        
        output = result.stdout
        lines = output.split('\n')
        
        counts = {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
        
        def parse_packet_count(count_str):
            """Parse packet count with K/M suffixes"""
            try:
                count_str = count_str.strip()
                if count_str.endswith('K'):
                    return int(float(count_str[:-1]) * 1000)
                elif count_str.endswith('M'):
                    return int(float(count_str[:-1]) * 1000000)
                elif count_str.endswith('G'):
                    return int(float(count_str[:-1]) * 1000000000)
                else:
                    return int(count_str)
            except (ValueError, IndexError):
                return 0
        
        for line in lines:
            if 'DROP' in line and line.strip():
                # Parse the line format: num pkts bytes target prot opt in out source destination
                parts = line.strip().split()
                if len(parts) >= 5:
                    try:
                        packet_count_str = parts[1]  # pkts column
                        packet_count = parse_packet_count(packet_count_str)
                        protocol = parts[4]  # prot column
                        
                        if protocol == '1':  # ICMP
                            counts["icmp"] = packet_count
                        elif protocol == '17':  # UDP
                            counts["udp"] = packet_count
                        elif protocol == '6':  # TCP (check for SYN flag)
                            # For TCP, check if it's specifically SYN packets
                            counts["tcp"] = packet_count  # Count all TCP drops
                    except (ValueError, IndexError):
                        continue
        
        counts["total"] = counts["udp"] + counts["icmp"] + counts["tcp"]
        return counts
        
    except Exception as e:
        print(f"❌ Error getting dropped packet counts: {e}")
        return {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}

def update_global_dropped_counters():
    """Update global dropped packet counters with proper increment tracking"""
    global global_dropped_packets, last_seen_counts
    
    with global_counter_lock:
        current_counts = get_dropped_packet_counts()
        
        # Handle counter resets (when current < last_seen, rules were flushed)
        if (current_counts["udp"] < last_seen_counts["udp"] or 
            current_counts["icmp"] < last_seen_counts["icmp"] or 
            current_counts["tcp"] < last_seen_counts["tcp"]):
            
            # Add the final counts from before the reset
            global_dropped_packets["udp"] += last_seen_counts["udp"]
            global_dropped_packets["icmp"] += last_seen_counts["icmp"]
            global_dropped_packets["tcp"] += last_seen_counts["tcp"]
            
            # Reset tracking to start fresh
            last_seen_counts = {"udp": 0, "icmp": 0, "tcp": 0, "total": 0}
        
        # Calculate increments since last check
        increment_udp = max(0, current_counts["udp"] - last_seen_counts["udp"])
        increment_icmp = max(0, current_counts["icmp"] - last_seen_counts["icmp"])
        increment_tcp = max(0, current_counts["tcp"] - last_seen_counts["tcp"])
        
        # Only add increments (avoid double counting)
        global_dropped_packets["udp"] += increment_udp
        global_dropped_packets["icmp"] += increment_icmp
        global_dropped_packets["tcp"] += increment_tcp
        global_dropped_packets["total"] = (global_dropped_packets["udp"] + 
                                         global_dropped_packets["icmp"] + 
                                         global_dropped_packets["tcp"])
        
        # Update last seen counts for next iteration
        last_seen_counts = current_counts.copy()
        
        return global_dropped_packets.copy()


def initialize_firewall_config():
    """Initialize firewall configuration file if it doesn't exist"""
    if not os.path.exists(FIREWALL_ACTION_PATH):
        print("📝 Creating default firewall configuration...")
        default_config = {
            "action": "none",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "status": "inactive"
        }
        
        with open(FIREWALL_ACTION_PATH, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        # Set initial firewall state to allow all
        allow_all_traffic()
        return "none"
    else:
        # Read existing config
        try:
            with open(FIREWALL_ACTION_PATH, 'r') as f:
                config = json.load(f)
            return config.get('action', 'none')
        except:
            return "none"

def update_firewall_action(action):
    """Update firewall rules based on action and store in JSON"""
    global current_fw_action
    
    with firewall_lock:
        if current_fw_action == action:
            return  # No change needed
        
        print(f"🔄 Changing firewall action from '{current_fw_action}' to '{action}'")
        
        # Apply new firewall rules
        success = False
        if action == "drop":
            flush_forward_rules()
            set_forward_policy("DROP")
            success = apply_block_rules()
        elif action == "ratelimit":
            flush_forward_rules()
            set_forward_policy("ACCEPT")
            success = apply_rate_limit_rules()
        elif action == "none":
            success = allow_all_traffic()
        else:
            print(f"❌ Unknown action: {action}, defaulting to allow all")
            success = allow_all_traffic()
            action = "none"
        
        if success:
            current_fw_action = action
            
            # Update JSON configuration with new format
            config = {
                "action": action,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "status": "active" if action != "none" else "inactive"
            }
            
            try:
                with open(FIREWALL_ACTION_PATH, 'w') as f:
                    json.dump(config, f, indent=2)
                
                print(f"✅ Firewall action updated to '{action}'")
                
            except Exception as e:
                print(f"❌ Error updating firewall config: {e}")
        else:
            print(f"❌ Failed to apply firewall action: {action}")

def read_action_config():
    """Read the action configuration from JSON file"""
    try:
        with open(FIREWALL_ACTION_PATH, 'r') as file:
            data = json.load(file)
        return data.get('action', 'none')
    
    except FileNotFoundError:
        print("⚠️ Firewall config not found, initializing...")
        return initialize_firewall_config()
    except json.JSONDecodeError:
        print("❌ Invalid JSON format in firewall config")
        return "none"
    except Exception as e:
        print(f"❌ Error reading firewall config: {e}")
        return "none"

def is_rate_limited():
    """Check if we're exceeding the rate limit of 800 packets per second"""
    current_time = time.time()
    
    # Remove timestamps older than 1 second
    while packet_timestamps and current_time - packet_timestamps[0] > 1.0:
        packet_timestamps.popleft()
    
    # Check if we're at the rate limit
    if len(packet_timestamps) >= RATE_LIMIT:
        return True
    
    # Add current timestamp
    packet_timestamps.append(current_time)
    return False

def monitor_firewall_changes():
    """Monitor for changes in firewall configuration and apply them"""
    last_action = current_fw_action
    
    while True:
        try:
            time.sleep(2)  # Check every 2 seconds
            
            new_action = read_action_config()
            if new_action != last_action:
                print(f"📋 Detected firewall config change: {last_action} → {new_action}")
                update_firewall_action(new_action)
                last_action = new_action
                
        except Exception as e:
            print(f"❌ Error in firewall monitoring: {e}")
            time.sleep(5)

# ========== JSON Storage Functions ==========
def store_attack_data(attack_type, features, rule_flags, ml_confidence=0.0, ml_detected=False):
    """Store attack data in JSON file with both session and global dropped packet counts"""
    try:
        with json_lock:
            # Get both session and global counts
            session_counts = get_current_session_counts()
            global_counts = get_global_cumulative_counts()
            
            # Read existing data
            attack_data = {}
            if os.path.exists(ATTACK_DATA_PATH):
                try:
                    with open(ATTACK_DATA_PATH, 'r') as f:
                        attack_data = json.load(f)
                except:
                    attack_data = {}
            
            # Initialize structure if needed
            if attack_type not in attack_data:
                attack_data[attack_type] = []
            
            # Add new attack record with both session and global counts
            record = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "features": features,
                "rule_flags": rule_flags,
                "ml_confidence": float(ml_confidence),
                "ml_detected": bool(ml_detected),
                "rule_detected": any(rule_flags.values()) if isinstance(rule_flags, dict) else bool(rule_flags),
                "firewall_action": current_fw_action,
                "dropped_packets_session": session_counts,
                "dropped_packets_global": global_counts
            }
            
            attack_data[attack_type].append(record)
            
            # Keep only last 100 records per attack type
            if len(attack_data[attack_type]) > 100:
                attack_data[attack_type] = attack_data[attack_type][-100:]
            
            # Write back to file
            with open(ATTACK_DATA_PATH, 'w') as f:
                json.dump(attack_data, f, indent=2)
                
    except Exception as e:
        print(f"❌ Error storing attack data: {e}")


def publish_features(attack_type, features, file_path):
    """Publish current features to JSON file with both session and global dropped packet counts"""
    try:
        with json_lock:
            # Get both session and global counts
            session_counts = get_current_session_counts()
            global_counts = get_global_cumulative_counts()

            # Add timestamp and firewall info with both count types
            features_with_meta = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "features": features,
                "firewall_action": current_fw_action,
                "dropped_packets_session": session_counts,
                "dropped_packets_global": global_counts
            }
            with open(file_path, "w") as f:
                json.dump(features_with_meta, f, indent=2)
    except Exception:
        pass  # Avoid crashing if file not writable

# ========== ML Model Loading Functions ==========
def load_udp_models():
    """Load UDP ML models with backup support"""
    global udp_ml_model, udp_backup_model, udp_ml_scaler, udp_ml_enabled
    
    print("📁 Loading UDP ML models...")
    
    try:
        # Try to load existing models
        if os.path.exists(UDP_MODEL_PATH) and os.path.exists(UDP_SCALER_PATH):
            udp_ml_model = joblib.load(UDP_MODEL_PATH)
            udp_ml_scaler = joblib.load(UDP_SCALER_PATH)
            
            # Load backup model if available
            if os.path.exists(UDP_BACKUP_MODEL_PATH):
                udp_backup_model = joblib.load(UDP_BACKUP_MODEL_PATH)
            else:
                udp_backup_model = udp_ml_model
            
            udp_ml_enabled = True
            print("✅ UDP ML models loaded successfully")
        else:
            print("❌ UDP ML model files not found")
            udp_ml_enabled = False
            
    except Exception as e:
        print(f"❌ Error loading UDP models: {e}")
        udp_ml_enabled = False

def load_icmp_models():
    """Load ICMP ML models"""
    global icmp_ml_model, icmp_backup_model, icmp_ml_scaler, icmp_ml_enabled
    
    print("📁 Loading ICMP ML models...")
    
    try:
        if os.path.exists(ICMP_MODEL_PATH) and os.path.exists(ICMP_SCALER_PATH):
            icmp_ml_model = joblib.load(ICMP_MODEL_PATH)
            icmp_ml_scaler = joblib.load(ICMP_SCALER_PATH)
            
            # Load backup model if available
            if os.path.exists(ICMP_BACKUP_MODEL_PATH):
                icmp_backup_model = joblib.load(ICMP_BACKUP_MODEL_PATH)
            else:
                icmp_backup_model = icmp_ml_model
                
            icmp_ml_enabled = True
            print("✅ ICMP ML models loaded successfully")
        else:
            print("❌ ICMP ML model files not found")
            icmp_ml_enabled = False
            
    except Exception as e:
        print(f"❌ Error loading ICMP models: {e}")
        icmp_ml_enabled = False

def load_syn_models():
    """Load SYN ML models with normalization"""
    global syn_ml_model, syn_backup_model, syn_ml_scaler, syn_confidence_normalizer
    global syn_ml_enabled, syn_normalizer_enabled
    
    print("📁 Loading SYN ML models...")
    
    try:
        if os.path.exists(SYN_MODEL_PATH) and os.path.exists(SYN_SCALER_PATH):
            syn_ml_model = joblib.load(SYN_MODEL_PATH)
            syn_ml_scaler = joblib.load(SYN_SCALER_PATH)
            
            # Load backup model if available
            if os.path.exists(SYN_BACKUP_MODEL_PATH):
                syn_backup_model = joblib.load(SYN_BACKUP_MODEL_PATH)
            else:
                syn_backup_model = syn_ml_model
                
            syn_ml_enabled = True
            print("✅ SYN ML models loaded successfully")
            
            # Load SYN confidence normalizer
            if os.path.exists(SYN_CONFIDENCE_NORMALIZER_PATH):
                syn_confidence_normalizer = joblib.load(SYN_CONFIDENCE_NORMALIZER_PATH)
                syn_normalizer_enabled = True
                print("✅ SYN confidence normalizer loaded successfully")
            else:
                print("❌ SYN confidence normalizer not found")
                syn_normalizer_enabled = False
        else:
            print("❌ SYN ML model files not found")
            syn_ml_enabled = False
            syn_normalizer_enabled = False
            
    except Exception as e:
        print(f"❌ Error loading SYN models: {e}")
        syn_ml_enabled = False
        syn_normalizer_enabled = False

# ========== UDP Detection Functions ==========
def detect_udp(pkt):
    global udp_large_payload_count, udp_last_packet_time
    
    if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
        return
    
    now = time.time()
    with udp_lock:
        udp_packet_times.append(now)
        
        # Track timing
        if udp_last_packet_time > 0:
            iat = now - udp_last_packet_time
            udp_inter_arrival_times.append(iat)
            if len(udp_inter_arrival_times) > 500:
                udp_inter_arrival_times.popleft()
        udp_last_packet_time = now
        
        # Track ports and IPs
        port = pkt[UDP].dport
        src_ip = pkt[IP].src
        udp_dst_port_counter[port] += 1
        udp_src_ip_counter[src_ip] += 1
        
        # Track packet sizes
        packet_size = len(pkt)
        udp_packet_sizes.append(packet_size)
        if len(udp_packet_sizes) > 500:
            udp_packet_sizes.popleft()
        
        # Track large payloads
        try:
            payload = bytes(pkt[UDP].payload)
            if len(payload) > UDP_LARGE_PAYLOAD_THRESHOLD:
                udp_large_payload_count += 1
        except:
            pass

def calculate_udp_adaptive_weight_multiplier(pps_triggered, ports_triggered, payload_triggered):
    """Calculate adaptive weight multiplier for UDP based on triggered features"""
    triggered_features = sum([pps_triggered, ports_triggered, payload_triggered])
    
    if triggered_features == 1 and pps_triggered:
        return PPS_WEIGHT_MULTIPLIER
    elif triggered_features == 2:
        return PPS_WEIGHT_MULTIPLIER * (1 - MULTI_FEATURE_REDUCTION)
    elif triggered_features == 3:
        return PPS_WEIGHT_MULTIPLIER * (1 - MULTI_FEATURE_REDUCTION - THREE_FEATURE_REDUCTION)
    else:
        return 1.0

def udp_extract_ml_features(pps, unique_ports, large_payload_count, unique_src_ips, pps_triggered, ports_triggered, payload_triggered):
    """Extract features for UDP ML prediction with adaptive weighting"""
    with udp_lock:
        # Calculate adaptive weight multiplier for PPS
        pps_weight_multiplier = calculate_udp_adaptive_weight_multiplier(pps_triggered, ports_triggered, payload_triggered)
        
        # Apply adaptive weight multiplier to PPS feature
        packet_rate = max(0, pps * pps_weight_multiplier)
        
        # Enhanced port diversity with higher weight for randomization attacks
        if ports_triggered:
            port_diversity = max(0, unique_ports * PORT_WEIGHT_MULTIPLIER)
        else:
            port_diversity = max(0, unique_ports)
        
        payload_anomaly = max(0, large_payload_count)
        
        # Create feature array
        features = [packet_rate, port_diversity, payload_anomaly]
        features = [0.0 if np.isnan(f) or np.isinf(f) else f for f in features]
        return np.array(features), pps_weight_multiplier

def calculate_udp_adaptive_confidence_boost(udp_pps, unique_ports, pps_triggered, ports_triggered, payload_triggered):
    """Calculate adaptive confidence boost for UDP"""
    triggered_features = sum([pps_triggered, ports_triggered, payload_triggered])
    total_boost = 0
    
    # PPS boost
    if udp_pps > UDP_RATE_THRESHOLD:
        pps_ratio = udp_pps / UDP_RATE_THRESHOLD
        pps_boost = min(PPS_CONFIDENCE_BOOST, PPS_CONFIDENCE_BOOST * (pps_ratio / 2))
        
        if triggered_features == 1 and pps_triggered:
            total_boost += pps_boost
        elif triggered_features == 2:
            total_boost += pps_boost * (1 - MULTI_FEATURE_REDUCTION)
        elif triggered_features == 3:
            total_boost += pps_boost * (1 - MULTI_FEATURE_REDUCTION - THREE_FEATURE_REDUCTION)
    
    # Enhanced port randomization boost
    if unique_ports > UDP_PORT_VARIATION_THRESHOLD:
        port_ratio = unique_ports / UDP_PORT_VARIATION_THRESHOLD
        port_boost = min(PORT_CONFIDENCE_BOOST, PORT_CONFIDENCE_BOOST * (port_ratio / 2))
        
        if triggered_features == 1 and ports_triggered:
            total_boost += port_boost * 1.5  # Extra boost for port-only attacks
        elif triggered_features == 2:
            total_boost += port_boost * (1 - MULTI_FEATURE_REDUCTION)
        elif triggered_features == 3:
            total_boost += port_boost * (1 - MULTI_FEATURE_REDUCTION - THREE_FEATURE_REDUCTION)
    
    return total_boost

def udp_ml_predict(features, udp_pps, unique_ports, pps_triggered, ports_triggered, payload_triggered):
    """Make UDP ML prediction with adaptive confidence scoring"""
    if not udp_ml_enabled:
        return 0, 0.0, 0.0
    
    # Check for zero/very low traffic
    if features[0] < 0.1:
        return 0, 0.0, 0.0
    
    try:
        features_reshaped = features.reshape(1, -1)
        features_scaled = udp_ml_scaler.transform(features_reshaped)
        
        prediction = udp_ml_model.predict(features_scaled)[0]
        score = udp_ml_model.decision_function(features_scaled)[0]
        backup_prediction = udp_backup_model.predict(features_scaled)[0] if udp_backup_model is not None else prediction
        
        if prediction == -1:  # Anomaly detected
            triggered_features = sum([pps_triggered, ports_triggered, payload_triggered])
            
            # Enhanced base confidence calculation
            if triggered_features == 3:
                base_confidence = min(75, abs(score) * 215)
            else:
                base_confidence = min(98, abs(score) * 240)
            
            # Enhanced confidence boost
            confidence_boost = calculate_udp_adaptive_confidence_boost(
                udp_pps, unique_ports, pps_triggered, ports_triggered, payload_triggered
            )
            base_confidence = min(99, base_confidence + confidence_boost)
            
            # Additional boost if both models agree
            if backup_prediction == -1:
                if triggered_features == 3:
                    base_confidence = min(99.0, base_confidence * 1.15)
                else:
                    base_confidence = min(99.5, base_confidence * 1.25)
            
            return 1, score, base_confidence
        else:
            return 0, score, 0.0  # Set confidence to 0 for normal traffic
            
    except Exception as e:
        print(f"❌ UDP ML prediction error: {e}")
        return 0, 0.0, 0.0

# ========== ICMP Detection Functions ==========
def detect_icmp(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(ICMP):
        return
    
    if pkt[ICMP].type != 8:  # Only ICMP Echo Request
        return

    now = time.time()
    src_ip = pkt[IP].src
    payload_size = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0

    with icmp_lock:        
        icmp_packet_times.append(now)
        icmp_source_ips[now].add(src_ip)
        icmp_payload_sizes.append(payload_size)

def calculate_adaptive_weight_multiplier(pps_triggered, ips_triggered, payload_triggered):
    """Calculate adaptive weight multiplier for ICMP"""
    triggered_features = sum([pps_triggered, ips_triggered, payload_triggered])
    
    if triggered_features == 1 and pps_triggered:
        return PPS_WEIGHT_MULTIPLIER
    elif triggered_features == 2:
        return PPS_WEIGHT_MULTIPLIER * (1 - MULTI_FEATURE_REDUCTION)
    elif triggered_features == 3:
        return PPS_WEIGHT_MULTIPLIER * (1 - MULTI_FEATURE_REDUCTION - THREE_FEATURE_REDUCTION)
    else:
        return 1.0

def icmp_extract_features(icmp_pps, unique_ips, large_payload_count, pps_triggered, ips_triggered, payload_triggered):
    """Extract features for ICMP ML"""
    with icmp_lock:
        weight_multiplier = calculate_adaptive_weight_multiplier(pps_triggered, ips_triggered, payload_triggered)
        icmp_rate = max(0, icmp_pps * weight_multiplier)
        ip_diversity = max(0, unique_ips)
        large_payloads = max(0, large_payload_count)
        
        features = [icmp_rate, ip_diversity, large_payloads]
        features = [0.0 if np.isnan(f) or np.isinf(f) else max(0.0, f) for f in features]
        return np.array(features), weight_multiplier

def calculate_adaptive_confidence_boost(icmp_pps, pps_triggered, ips_triggered, payload_triggered):
    """Calculate adaptive confidence boost for ICMP"""
    triggered_features = sum([pps_triggered, ips_triggered, payload_triggered])
    
    if icmp_pps > ICMP_PPS_THRESHOLD:
        pps_ratio = icmp_pps / ICMP_PPS_THRESHOLD
        base_boost = min(PPS_CONFIDENCE_BOOST, PPS_CONFIDENCE_BOOST * (pps_ratio / 2))
        
        if triggered_features == 1 and pps_triggered:
            return base_boost
        elif triggered_features == 2:
            return base_boost * (1 - MULTI_FEATURE_REDUCTION)
        elif triggered_features == 3:
            return base_boost * (1 - MULTI_FEATURE_REDUCTION - THREE_FEATURE_REDUCTION)
    
    return 0

def icmp_ml_predict(features, icmp_pps, pps_triggered, ips_triggered, 
                    payload_triggered):
    """Make ICMP ML prediction"""
    if not icmp_ml_enabled:
        return 0, 0.0, 0.0
    
    # Check for zero/very low traffic
    if features[0] < 0.1:
        return 0, 0.0, 0.0
    
    try:
        features_reshaped = features.reshape(1, -1)
        features_scaled = icmp_ml_scaler.transform(features_reshaped)
        
        prediction = icmp_ml_model.predict(features_scaled)[0]
        score = icmp_ml_model.decision_function(features_scaled)[0]
        backup_prediction = icmp_backup_model.predict(features_scaled)[0] if icmp_backup_model is not None else prediction
        
        if prediction == -1:
            triggered_features = sum([pps_triggered, ips_triggered, payload_triggered])
            
            if triggered_features == 3:
                base_confidence = min(75, abs(score) * 230)
            else:
                base_confidence = min(98, abs(score) * 240)
            
            pps_boost = calculate_adaptive_confidence_boost(icmp_pps, pps_triggered, ips_triggered, payload_triggered)
            base_confidence = min(99, base_confidence + pps_boost)
            
            if backup_prediction == -1:
                if triggered_features == 3:
                    base_confidence = min(99.0, base_confidence * 1.15)
                else:
                    base_confidence = min(99.5, base_confidence * 1.25)
            
            return 1, score, base_confidence
        else:
            return 0, score, 0.0  # Set confidence to 0 for normal traffic
            
    except Exception as e:
        print(f"❌ ICMP ML prediction error: {e}")
        return 0, 0.0, 0.0

# ========== SYN Detection Functions ==========
def detect_syn(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    now = time.time()
    sport = pkt[TCP].sport  # Source port
    dport = pkt[TCP].dport  # Destination port
    flags = pkt[TCP].flags
    packet_size = len(pkt)

    with syn_lock:        
        if flags == "S":  # SYN packet
            syn_packet_times.append(now)
            syn_source_ports.append(sport)    # Track source ports in sliding window
            syn_dest_ports.append(dport)      # Track destination ports
            syn_packet_sizes.append(packet_size)
            
            # Keep deques manageable
            if len(syn_source_ports) > 1000:
                syn_source_ports.popleft()
            if len(syn_dest_ports) > 1000:
                syn_dest_ports.popleft()

def syn_extract_features(syn_pps, unique_sports, avg_pkt_size):
    """Extract features for SYN ML"""
    with syn_lock:
        syn_rate = max(0, syn_pps)
        port_diversity = max(0, unique_sports)
        packet_size_avg = max(0, avg_pkt_size)
        
        features = [syn_rate, port_diversity, packet_size_avg]
        features = [0.0 if np.isnan(f) or np.isinf(f) else max(0.0, f) for f in features]
        return np.array(features)

def syn_normalize_confidence(original_confidence):
    """Normalize SYN confidence using trained model"""
    if original_confidence < 1.0:  # Very low confidence for near-zero traffic
        return 0.0
        
    if not syn_normalizer_enabled:
        if original_confidence < 15:
            return 0.0
        elif original_confidence <= 45:
            return original_confidence * 2.1
        elif original_confidence <= 54:
            return 93.0 + (original_confidence - 45) * 0.17
        else:
            return 94.5 + (original_confidence - 54) * 0.04
    
    try:
        input_conf = np.array([[original_confidence]])
        normalized_conf = syn_confidence_normalizer.predict(input_conf)[0]
        return max(0.0, min(96.5, normalized_conf))
    except Exception as e:
        print(f"❌ SYN confidence normalization error: {e}")
        return original_confidence

def syn_ml_predict(features):
    """Make SYN ML prediction with normalization"""
    if not syn_ml_enabled:
        return 0, 0.0, 0.0
    
    # Check for zero/very low traffic
    if features[0] < 0.1:
        return 0, 0.0, 0.0
    
    try:
        features_reshaped = features.reshape(1, -1)
        features_scaled = syn_ml_scaler.transform(features_reshaped)
        
        prediction = syn_ml_model.predict(features_scaled)[0]
        score = syn_ml_model.decision_function(features_scaled)[0]
        backup_prediction = syn_backup_model.predict(features_scaled)[0] if syn_backup_model is not None else prediction
        
        if prediction == -1:
            base_confidence = min(98, abs(score) * 220)
            if backup_prediction == -1:
                base_confidence = min(99, base_confidence * 1.35)
            
            # Apply normalization
            normalized_confidence = syn_normalize_confidence(base_confidence)
            return 1, score, normalized_confidence
        else:
            return 0, score, 0.0  # Set confidence to 0 for normal traffic
            
    except Exception as e:
        print(f"❌ SYN ML prediction error: {e}")
        return 0, 0.0, 0.0

# ========== Attack State Management ==========
def update_attack_state(attack_type, is_attack_detected, current_time):
    """Update attack state and handle transitions"""
    global udp_attack_active, udp_last_attack_time, udp_normal_periods
    global icmp_attack_active, icmp_last_attack_time, icmp_normal_periods
    global syn_attack_active, syn_last_attack_time, syn_normal_periods
    
    if attack_type == "UDP":
        if is_attack_detected:
            if not udp_attack_active:
                print(f"\n🔥 UDP ATTACK STARTED at {time.strftime('%H:%M:%S')}")
                udp_attack_active = True
            udp_last_attack_time = current_time
            udp_normal_periods = 0
        else:
            if udp_attack_active:
                udp_normal_periods += 1
                if udp_normal_periods >= NORMAL_THRESHOLD_PERIODS:
                    duration = current_time - udp_last_attack_time
                    print(f"\n✅ UDP ATTACK ENDED - Duration: {duration:.1f}s - Traffic returned to normal")
                    udp_attack_active = False
                    udp_normal_periods = 0
    
    elif attack_type == "ICMP":
        if is_attack_detected:
            if not icmp_attack_active:
                print(f"\n🔥 ICMP ATTACK STARTED at {time.strftime('%H:%M:%S')}")
                icmp_attack_active = True
            icmp_last_attack_time = current_time
            icmp_normal_periods = 0
        else:
            if icmp_attack_active:
                icmp_normal_periods += 1
                if icmp_normal_periods >= NORMAL_THRESHOLD_PERIODS:
                    duration = current_time - icmp_last_attack_time
                    print(f"\n✅ ICMP ATTACK ENDED - Duration: {duration:.1f}s - Traffic returned to normal")
                    icmp_attack_active = False
                    icmp_normal_periods = 0
    
    elif attack_type == "SYN":
        if is_attack_detected:
            if not syn_attack_active:
                print(f"\n🔥 SYN ATTACK STARTED at {time.strftime('%H:%M:%S')}")
                syn_attack_active = True
            syn_last_attack_time = current_time
            syn_normal_periods = 0
        else:
            if syn_attack_active:
                syn_normal_periods += 1
                if syn_normal_periods >= NORMAL_THRESHOLD_PERIODS:
                    duration = current_time - syn_last_attack_time
                    print(f"\n✅ SYN ATTACK ENDED - Duration: {duration:.1f}s - Traffic returned to normal")
                    syn_attack_active = False
                    syn_normal_periods = 0

# ========== Packet Detection ==========
def detect_threats_and_act(pkt):
    """Main packet detection function"""
    global current_pkt

    if pkt.haslayer(UDP):
        detect_udp(pkt)
    elif pkt.haslayer(ICMP):
        detect_icmp(pkt)
    elif pkt.haslayer(TCP):
        detect_syn(pkt)

    current_pkt = pkt

# ========== Alert Functions ==========
def print_udp_ml_alert(anomaly_score, confidence, weight_multiplier, triggered_features):
    confidence_level = "🟢 LOW" if confidence < 40 else "🟡 MEDIUM" if confidence < 70 else "🔴 HIGH"
    threat_indicator = "⚠️" if confidence < 50 else "🚨" if confidence < 80 else "💀"
    
    print(f"\n🤖 ML ALERT: AI Detected UDP Flood Attack {threat_indicator}")
    print(f"     🎯 Anomaly Score: {anomaly_score:.4f}")
    print(f"     📊 ML Confidence: {confidence:.1f}% [{confidence_level}]")
    # print(f"     📈 Weight Multiplier: {weight_multiplier:.2f}x")
    print(f"     🔢 Triggered Features: {triggered_features}")
    print(f"     🔍 ML Model Status: {'ACTIVE' if udp_ml_enabled else 'NOT_TRAINED'}")
    print(f"     🔍 ML Prediction: ATTACK DETECTED")
    print(f"     🛡️ Current Firewall: {current_fw_action.upper()}")
    
    if confidence > 95:
        print(f"     🚨 CRITICAL: Immediate action recommended!")
    elif confidence > 80:
        print(f"     ⚠️  HIGH: Monitor closely and prepare mitigation")
    elif confidence > 60:
        print(f"     🟡 MEDIUM: Potential threat - continue monitoring")
    else:
        print(f"     🔍 LOW: Possible false positive - verify manually")
    
    print("--------------------------------------------------")

def print_icmp_ml_alert(anomaly_score, confidence, weight_multiplier, triggered_features):
    confidence_level = "🟢 LOW" if confidence < 40 else "🟡 MEDIUM" if confidence < 70 else "🔴 HIGH"
    threat_indicator = "⚠️" if confidence < 50 else "🚨" if confidence < 80 else "💀"
    
    print(f"\n🤖 ML ALERT: AI Detected ICMP Flood Attack {threat_indicator}")
    print(f"     🎯 Anomaly Score: {anomaly_score:.4f}")
    print(f"     📊 ML Confidence: {confidence:.1f}% [{confidence_level}]")
    print(f"     📈 Weight Multiplier: {weight_multiplier:.2f}x")
    print(f"     🔢 Triggered Features: {triggered_features}")
    print(f"     🔍 ML Model Status: {'ACTIVE' if icmp_ml_enabled else 'NOT_TRAINED'}")
    print(f"     🔍 ML Prediction: ATTACK DETECTED")
    print(f"     🛡️ Current Firewall: {current_fw_action.upper()}")
    
    if confidence > 95:
        print(f"     🚨 CRITICAL: Immediate action recommended!")
    elif confidence > 80:
        print(f"     ⚠️  HIGH: Monitor closely and prepare mitigation")
    elif confidence > 60:
        print(f"     🟡 MEDIUM: Potential threat - continue monitoring")
    else:
        print(f"     🔍 LOW: Possible false positive - verify manually")
    
    print("--------------------------------------------------")

def print_syn_ml_alert(anomaly_score, confidence, normalized_confidence):
    confidence_level = "🟢 LOW" if normalized_confidence < 40 else "🟡 MEDIUM" if normalized_confidence < 70 else "🔴 HIGH"
    threat_indicator = "⚠️" if normalized_confidence < 50 else "🚨" if normalized_confidence < 80 else "💀"
    
    print(f"\n🤖 ML ALERT: AI Detected SYN Flood Attack {threat_indicator}")
    print(f"     🎯 Anomaly Score: {anomaly_score:.4f}")
    print(f"     📊 Raw Confidence: {confidence:.1f}%")
    print(f"     🧠 Normalized Confidence: {normalized_confidence:.1f}% [{confidence_level}]")
    print(f"     🔍 ML Model Status: {'ACTIVE' if syn_ml_enabled else 'NOT_TRAINED'}")
    print(f"     🔍 ML Prediction: ATTACK DETECTED")
    print(f"     🛡️ Current Firewall: {current_fw_action.upper()}")
    
    if normalized_confidence > 95:
        print(f"     🚨 CRITICAL: Immediate action recommended!")
    elif normalized_confidence > 80:
        print(f"     ⚠️  HIGH: Monitor closely and prepare mitigation")
    elif normalized_confidence > 60:
        print(f"     🟡 MEDIUM: Potential threat - continue monitoring")
    else:
        print(f"     🔍 LOW: Possible false positive - verify manually")
    
    print("--------------------------------------------------")

def print_traffic_state_change(attack_type, pps, traffic_state):
    """Print traffic state changes"""
    if traffic_state == "ZERO_TRAFFIC":
        print(f"🟢 {attack_type} Traffic: ZERO ({pps:.2f} PPS) - Network quiet")
    elif traffic_state == "LOW_TRAFFIC":
        print(f"🟡 {attack_type} Traffic: LOW ({pps:.2f} PPS) - Minimal activity")
    elif traffic_state == "NORMAL_TRAFFIC":
        print(f"🔵 {attack_type} Traffic: NORMAL ({pps:.2f} PPS) - Baseline activity")
    elif traffic_state == "ELEVATED_TRAFFIC":
        print(f"🟠 {attack_type} Traffic: ELEVATED ({pps:.2f} PPS) - Increased activity")

def get_traffic_emoji(pps, protocol):
    """Get appropriate emoji for traffic level"""
    if pps < 0.1:
        return "💤"  # Zero traffic
    elif pps < MIN_TRAFFIC_THRESHOLD:
        return "🔹"  # Low traffic
    elif pps < 100:
        return "🔵"  # Normal traffic
    elif pps < 500:
        return "🟡"  # Elevated traffic
    elif pps < 1000:
        return "🟠"  # High traffic
    else:
        return "🔥"  # Very high traffic

# ========== Main Analysis Loop ==========
def analyze_traffic():
    global current_pkt
    global udp_flood_pps_variant, udp_flood_large_payload_variant, udp_flood_port_variation_variant, udp_ml_detection_flag
    global icmp_flood_pps_variant, icmp_flood_large_payload_variant, icmp_flood_spoofed_ips_variant, icmp_ml_detection_flag
    global syn_flood_pps_variant, syn_flood_port_variant, syn_flood_size_variant, syn_ml_detection_flag
    global udp_large_payload_count

    """Main traffic analysis loop"""
    while True:
        time.sleep(WINDOW_SIZE)
        now = time.time()
        
      # Get current and global dropped packet counts
        session_counts = get_current_session_counts()
        global_counts = get_global_cumulative_counts()
        update_global_dropped_counters()  # Update the tracking
        

        # ========== UDP Analysis ==========
        with udp_lock:
            # Clean old UDP packets
            while udp_packet_times and udp_packet_times[0] < now - WINDOW_SIZE:
                udp_packet_times.popleft()
            
            udp_pps = len(udp_packet_times) / WINDOW_SIZE
            udp_unique_ports = len(udp_dst_port_counter)
            udp_unique_src_ips = len(udp_src_ip_counter)
        
        # UDP Rule-based detection
        udp_flood_pps_variant = int(udp_pps > UDP_RATE_THRESHOLD)
        udp_flood_large_payload_variant = int(udp_large_payload_count > 10)
        udp_flood_port_variation_variant = int(udp_unique_ports > UDP_PORT_VARIATION_THRESHOLD)
        
        udp_rule_detected = udp_flood_pps_variant or udp_flood_large_payload_variant or udp_flood_port_variation_variant
        udp_ml_confidence = 0.0
        udp_ml_detected = False
        udp_weight_multiplier = 1.0
        
        # UDP ML Processing
        try:
            udp_features, udp_weight_multiplier = udp_extract_ml_features(
                udp_pps, udp_unique_ports, udp_large_payload_count, udp_unique_src_ips,
                udp_flood_pps_variant, udp_flood_port_variation_variant, udp_flood_large_payload_variant
            )
            
            # ML prediction - Only if model is enabled
            if udp_ml_enabled:
                udp_ml_prediction, udp_anomaly_score, udp_confidence_raw = udp_ml_predict(
                    udp_features, udp_pps, udp_unique_ports,
                    udp_flood_pps_variant, udp_flood_port_variation_variant, udp_flood_large_payload_variant
                )
                
                if udp_ml_prediction == 1:
                    udp_triggered_features = sum([udp_flood_pps_variant, udp_flood_port_variation_variant, udp_flood_large_payload_variant])
                    
                    # Print ML alert  
                    print_udp_ml_alert(udp_anomaly_score, udp_confidence_raw, udp_weight_multiplier, udp_triggered_features)

                    # Set detection flags
                    udp_ml_detection_flag = 1
                    udp_ml_detected = True
                    udp_ml_confidence = udp_confidence_raw
                else:
                    udp_ml_detection_flag = 0
                    udp_ml_confidence = 0.0
            else:
                # Calculate rule-based confidence with adaptive weighting
                rule_confidence = 0.0
                if udp_rule_detected:
                    udp_triggered_features = sum([udp_flood_pps_variant, udp_flood_port_variation_variant, udp_flood_large_payload_variant])
                    if udp_triggered_features == 3:
                        rule_confidence = 70.0
                    else:
                        rule_confidence = 85.0
                        
                    # Apply enhanced confidence boost
                    confidence_boost = calculate_udp_adaptive_confidence_boost(
                        udp_pps, udp_unique_ports, udp_flood_pps_variant, 
                        udp_flood_port_variation_variant, udp_flood_large_payload_variant
                    )
                    rule_confidence += confidence_boost
                    
                    # Cap confidence based on number of features
                    if udp_triggered_features == 3:
                        rule_confidence = min(85.0, rule_confidence)
                    else:
                        rule_confidence = min(99.0, rule_confidence)
                        
                udp_ml_confidence = rule_confidence
        
        except Exception as e:
            print(f"❌ UDP ML processing error: {e}")
        
        # Update UDP attack state
        udp_attack_detected = udp_rule_detected 
        update_attack_state("UDP", udp_attack_detected, now)
        
        # ========== ICMP Analysis ==========
        with icmp_lock:
            # Clean old ICMP packets
            while icmp_packet_times and icmp_packet_times[0] < now - WINDOW_SIZE:
                icmp_packet_times.popleft()

            icmp_pps = len(icmp_packet_times) / WINDOW_SIZE

            # Unique source IPs
            icmp_active_ips = set()
            icmp_expired_keys = []
            for t, ips in icmp_source_ips.items():
                if t < now - WINDOW_SIZE:
                    icmp_expired_keys.append(t)
                else:
                    icmp_active_ips |= ips
            for k in icmp_expired_keys:
                del icmp_source_ips[k]
            icmp_unique_ips = len(icmp_active_ips)

            # Count large payloads
            icmp_large_payload_count = sum(1 for size in icmp_payload_sizes if size > ICMP_LARGE_PAYLOAD_THRESHOLD)

        # ICMP Rule-based detection
        icmp_flood_pps_variant = int(icmp_pps > ICMP_PPS_THRESHOLD)
        icmp_flood_spoofed_ips_variant = int(icmp_unique_ips > ICMP_UNIQUE_IP_THRESHOLD)
        icmp_flood_large_payload_variant = int(icmp_large_payload_count > 10)
        
        icmp_rule_detected = icmp_flood_pps_variant or icmp_flood_spoofed_ips_variant or icmp_flood_large_payload_variant
        icmp_ml_confidence = 0.0
        icmp_ml_detected = False
        icmp_triggered_features = sum([icmp_flood_pps_variant, icmp_flood_spoofed_ips_variant, icmp_flood_large_payload_variant])
        
        # ICMP ML Processing
        if icmp_ml_enabled:
            try:
                icmp_features, icmp_weight_multiplier = icmp_extract_features(
                    icmp_pps, icmp_unique_ips, icmp_large_payload_count,
                    icmp_flood_pps_variant, icmp_flood_spoofed_ips_variant, icmp_flood_large_payload_variant
                )
                icmp_ml_prediction, icmp_anomaly_score, icmp_confidence_raw = icmp_ml_predict(
                    icmp_features, icmp_pps, 
                    icmp_flood_pps_variant, icmp_flood_spoofed_ips_variant, icmp_flood_large_payload_variant
                )
                
                if icmp_ml_prediction == 1:
                    print_icmp_ml_alert(icmp_anomaly_score, icmp_confidence_raw, icmp_weight_multiplier, icmp_triggered_features)
                    icmp_ml_detection_flag = 1
                    icmp_ml_detected = True
                    icmp_ml_confidence = icmp_confidence_raw
                else:
                    icmp_ml_detection_flag = 0
                    icmp_ml_confidence = 0.0
            except Exception as e:
                print(f"❌ ICMP ML processing error: {e}")
        
        # Update ICMP attack state
        icmp_attack_detected = icmp_rule_detected
        update_attack_state("ICMP", icmp_attack_detected, now)
        
        # ========== SYN Analysis ==========
        with syn_lock:
            # Clean old SYN packets
            while syn_packet_times and syn_packet_times[0] < now - WINDOW_SIZE:
                syn_packet_times.popleft()

            syn_pps = len(syn_packet_times) / WINDOW_SIZE

            # Calculate unique source ports from the sliding window
            syn_unique_sports = len(set(syn_source_ports))

            syn_avg_pkt_size = sum(syn_packet_sizes) / len(syn_packet_sizes) if syn_packet_sizes else 0

        # SYN Rule-based detection
        syn_flood_pps_variant = int(syn_pps > SYN_PPS_THRESHOLD)
        syn_flood_port_variant = int(syn_unique_sports > SYN_UNIQUE_SPORT_THRESHOLD)
        # Only trigger size-based detection if there's also elevated traffic
        syn_flood_size_variant = int(syn_avg_pkt_size < SYN_AVG_PKT_SIZE_THRESHOLD and 
                                    syn_avg_pkt_size > 10 and 
                                    syn_pps > 50)  # Add minimum PPS requirement
        
        syn_rule_detected = syn_flood_pps_variant or syn_flood_port_variant or syn_flood_size_variant
        syn_ml_confidence = 0.0
        syn_ml_detected = False
        
        # SYN ML Processing
        try:
            syn_features = syn_extract_features(syn_pps, syn_unique_sports, syn_avg_pkt_size)
            
            # ML prediction - Only if model is enabled
            if syn_ml_enabled:
                syn_ml_prediction, syn_anomaly_score, syn_confidence_raw = syn_ml_predict(syn_features)
                
                if syn_ml_prediction == 1:
                    print_syn_ml_alert(syn_anomaly_score, syn_confidence_raw, syn_confidence_raw)
                    syn_ml_detection_flag = 1
                    syn_ml_detected = True
                    syn_ml_confidence = syn_confidence_raw
                else:
                    syn_ml_detection_flag = 0
                    syn_ml_confidence = 0.0
            else:
                # Calculate rule-based confidence
                rule_confidence = 0.0
                if syn_rule_detected:
                    syn_triggered_features = sum([syn_flood_pps_variant, syn_flood_port_variant, syn_flood_size_variant])
                    if syn_triggered_features == 3:
                        rule_confidence = 70.0
                    else:
                        rule_confidence = 85.0
                        
                    # Apply normalization to rule-based confidence
                    rule_confidence = syn_normalize_confidence(rule_confidence)
                        
                syn_ml_confidence = rule_confidence
        
        except Exception as e:
            print(f"❌ SYN ML processing error: {e}")
        
        # Update SYN attack state
        syn_attack_detected = syn_rule_detected 
        update_attack_state("SYN", syn_attack_detected, now)
        
        # ========== Status Display ==========
        print(f"\n📊 Enhanced DDoS Detection Dashboard [{time.strftime('%H:%M:%S')}]")
        print("   " + "=" * 70)
        
        # Firewall Status
        print(f"  🛡️ FIREWALL STATUS:")
        print(f"     🔧 Current Action: {current_fw_action.upper()}")
        print(f"     📊 Session Dropped: UDP={session_counts['udp']}, ICMP={session_counts['icmp']}, TCP={session_counts['tcp']}")
        print(f"     🔢 Session Total: {session_counts['total']}")
        print(f"     🌍 Global Dropped: UDP={global_counts['udp']}, ICMP={global_counts['icmp']}, TCP={global_counts['tcp']}")
        print(f"     🌍 Global Total: {global_counts['total']}")
        
        # UDP Status
        print(f"  🔵 UDP FLOOD DETECTION:")
        print(f"     📦 Packet Rate (PPS): {udp_pps:.2f} {get_traffic_emoji(udp_pps, 'UDP')}")
        print(f"     🔁 Unique Dest Ports: {udp_unique_ports}")
        print(f"     🌐 Unique Source IPs: {udp_unique_src_ips}")
        print(f"     💾 Large Payload Count: {udp_large_payload_count}")
        print(f"     🎯 Attack Status: {'🔥 ACTIVE' if udp_attack_active else '✅ CLEAR'}")
        
        if udp_ml_enabled:
            confidence_indicator = "🟢" if udp_ml_confidence < 30 else "🟡" if udp_ml_confidence < 70 else "🔴"
            print(f"     📊 ML Confidence: {udp_ml_confidence:.1f}% {confidence_indicator}")
        
        if udp_rule_detected:
            print(f"\n🚨 UDP RULE-BASED ALERT: 🔥 UDP Flood Attack Detected")
            print("   ⚙️  Threshold-Based Detection:")
            
            if udp_flood_pps_variant:
                print(f"     📊 High PPS: Exceeds {UDP_RATE_THRESHOLD} packets/sec")
            
            if udp_flood_large_payload_variant:
                print(f"     💾 Large Payloads: >10 packets exceeding {UDP_LARGE_PAYLOAD_THRESHOLD} bytes")
            
            if udp_flood_port_variation_variant:
                print(f"     🔄 Port Scanning: >{UDP_PORT_VARIATION_THRESHOLD} unique destination ports")
            
            print("--------------------------------------------------")
        
        # ICMP Status
        print(f"  🟡 ICMP FLOOD DETECTION:")
        print(f"     📦 ICMP PPS          : {icmp_pps:.2f} {get_traffic_emoji(icmp_pps, 'ICMP')}")
        print(f"     🔢 Unique Src IPs    : {icmp_unique_ips}")
        print(f"     📏 Large Payloads    : {icmp_large_payload_count} (> {ICMP_LARGE_PAYLOAD_THRESHOLD} bytes)")
        print(f"     ⚡ Triggered Features : {icmp_triggered_features}/3")
        print(f"     🎯 Attack Status: {'🔥 ACTIVE' if icmp_attack_active else '✅ CLEAR'}")
        
        if icmp_ml_enabled:
            confidence_indicator = "🟢" if icmp_ml_confidence < 30 else "🟡" if icmp_ml_confidence < 70 else "🔴"
            print(f"     📊 ML Confidence     : {icmp_ml_confidence:.1f}% {confidence_indicator}")
        
        if icmp_rule_detected:
            if icmp_flood_pps_variant:
                base_pps_conf = min(100, (icmp_pps / ICMP_PPS_THRESHOLD) * 110)
                adaptive_boost = calculate_adaptive_confidence_boost(
                    icmp_pps, icmp_flood_pps_variant,
                    icmp_flood_spoofed_ips_variant, icmp_flood_large_payload_variant
                )
                pps_conf = min(100, base_pps_conf + adaptive_boost)
                print(f"🚨 Feature 1 Detected: High ICMP PPS (Confidence: {pps_conf:.1f}%) 🔥")
            
            if icmp_flood_spoofed_ips_variant:
                ip_conf = min(100, (icmp_unique_ips / ICMP_UNIQUE_IP_THRESHOLD) * 105)
                print(f"🚨 Feature 2 Detected: Spoofed ICMP Flood (Confidence: {ip_conf:.1f}%)")
            
            if icmp_flood_large_payload_variant:
                payload_conf = min(100, (icmp_large_payload_count / 10) * 105)
                print(f"🚨 Feature 3 Detected: Large Payload ICMP Flood (Confidence: {payload_conf:.1f}%)")
            
            attack_type = "PPS-Only" if icmp_triggered_features == 1 and icmp_flood_pps_variant else f"Multi-Feature ({icmp_triggered_features})"
            print(f"\n🚨 ICMP RULE-BASED ALERT: {attack_type} ICMP Flood Attack Detected")
            print("--------------------------------------------------")
        
        # SYN Status
        print(f"  🟣 SYN FLOOD DETECTION:")
        print(f"     📦 SYN PPS           : {syn_pps:.2f} {get_traffic_emoji(syn_pps, 'SYN')}")
        print(f"     🔢 Unique Src Ports  : {syn_unique_sports}")
        print(f"     📏 Avg Packet Size   : {syn_avg_pkt_size:.2f} bytes")
        print(f"     🎯 Attack Status: {'🔥 ACTIVE' if syn_attack_active else '✅ CLEAR'}")
        
        if syn_ml_enabled:
            confidence_indicator = "🟢" if syn_ml_confidence < 30 else "🟡" if syn_ml_confidence < 70 else "🔴"
            print(f"     📊 ML Confidence     : {syn_ml_confidence:.1f}% {confidence_indicator}")
        
        if syn_rule_detected:
            if syn_flood_pps_variant:
                pps_conf = min(100, (syn_pps / SYN_PPS_THRESHOLD) * 105)
                norm_pps_conf = syn_normalize_confidence(pps_conf)
                print(f"🚨 Feature 1 Detected: High SYN PPS (Raw: {pps_conf:.1f}%, Enhanced: {norm_pps_conf:.1f}%)")
            if syn_flood_port_variant:
                port_conf = min(100, (syn_unique_sports / SYN_UNIQUE_SPORT_THRESHOLD) * 105)
                norm_port_conf = syn_normalize_confidence(port_conf)
                print(f"🚨 Feature 2 Detected: High Unique Src Ports (Raw: {port_conf:.1f}%, Enhanced: {norm_port_conf:.1f}%)")
            if syn_flood_size_variant:
                size_conf = min(100, (SYN_AVG_PKT_SIZE_THRESHOLD / max(syn_avg_pkt_size, 1)) * 105)
                norm_size_conf = syn_normalize_confidence(size_conf)
                print(f"🚨 Feature 3 Detected: Low Avg Packet Size (Raw: {size_conf:.1f}%, Enhanced: {norm_size_conf:.1f}%)")
            
            print(f"\n🚨 SYN RULE-BASED ALERT: SYN Flood Attack Detected")
            print("--------------------------------------------------")
        
        # Store attack data and publish features for all protocols (including normal states)
        udp_features_data = {
            "pps": float(udp_pps),
            "unique_ports": int(udp_unique_ports),
            "large_payload_count": int(udp_large_payload_count),
            "ml_confidence": float(udp_ml_confidence),
            "attack_active": udp_attack_active,
            "dropped_packets_session": session_counts['udp'],
            "dropped_packets_global": global_counts['udp']
        }

        udp_rule_flags = {
            "pps_variant": bool(udp_flood_pps_variant),
            "large_payload_variant": bool(udp_flood_large_payload_variant),
            "port_variation_variant": bool(udp_flood_port_variation_variant)
        }
        
        icmp_features_data = {
            "pps": float(icmp_pps),
            "unique_ips": int(icmp_unique_ips),
            "large_payloads": int(icmp_large_payload_count),
            "ml_confidence": float(icmp_ml_confidence),
            "attack_active": icmp_attack_active,
            "dropped_packets_session": session_counts['icmp'],
            "dropped_packets_global": global_counts['icmp']
        }

        icmp_rule_flags = {
            "pps_variant": bool(icmp_flood_pps_variant),
            "spoofed_ips_variant": bool(icmp_flood_spoofed_ips_variant),
            "large_payload_variant": bool(icmp_flood_large_payload_variant)
        }
        
        syn_features_data = {
            "pps": float(syn_pps),
            "unique_sports": int(syn_unique_sports),
            "avg_packet_size": float(syn_avg_pkt_size),
            "ml_confidence": float(syn_ml_confidence),
            "attack_active": syn_attack_active,
            "dropped_packets_session": session_counts['tcp'],
            "dropped_packets_global": global_counts['tcp']
        }

        syn_rule_flags = {
            "pps_variant": bool(syn_flood_pps_variant),
            "port_variant": bool(syn_flood_port_variant),
            "size_variant": bool(syn_flood_size_variant)
        }
        
        # Always publish features (for monitoring normal states too)
        publish_features("UDP", udp_features_data, UDP_FEATURES_PATH)
        publish_features("ICMP", icmp_features_data, ICMP_FEATURES_PATH)
        publish_features("SYN", syn_features_data, SYN_FEATURES_PATH)
        
        # Store attack data only when attacks are detected
        if udp_attack_detected:
            store_attack_data("UDP_FLOOD", udp_features_data, udp_rule_flags, udp_ml_confidence, udp_ml_detected)
        
        if icmp_attack_detected:
            store_attack_data("ICMP_FLOOD", icmp_features_data, icmp_rule_flags, icmp_ml_confidence, icmp_ml_detected)
        
        if syn_attack_detected:
            store_attack_data("SYN_FLOOD", syn_features_data, syn_rule_flags, syn_ml_confidence, syn_ml_detected)
        
        # ML Status Summary
        print(f"  🤖 ML MODELS STATUS:")
        print(f"     UDP ML: {'✅ ACTIVE' if udp_ml_enabled else '❌ DISABLED'}")
        print(f"     ICMP ML: {'✅ ACTIVE' if icmp_ml_enabled else '❌ DISABLED'}")
        print(f"     SYN ML: {'✅ ACTIVE' if syn_ml_enabled else '❌ DISABLED'}")
        print(f"     SYN Normalizer: {'✅ ACTIVE' if syn_normalizer_enabled else '❌ DISABLED'}")
        
        # Overall System Status
        any_attack_active = udp_attack_active or icmp_attack_active or syn_attack_active
        print(f"\n  🎯 OVERALL SYSTEM STATUS: {'🚨 UNDER ATTACK' if any_attack_active else '✅ ALL CLEAR'}")
        
        if any_attack_active:
            active_attacks = []
            if udp_attack_active:
                active_attacks.append("UDP")
            if icmp_attack_active:
                active_attacks.append("ICMP")
            if syn_attack_active:
                active_attacks.append("SYN")
            print(f"     🔥 Active Attacks: {', '.join(active_attacks)}")
        
        # Reset counters
        udp_dst_port_counter.clear()
        udp_src_ip_counter.clear()
        udp_large_payload_count = 0
        icmp_payload_sizes.clear()
        syn_packet_sizes.clear()

# ========== Main Entry Point ==========
if __name__ == "__main__":
    print("🎓 ENHANCED UNIFIED DDOS DETECTION SYSTEM WITH IPTABLES INTEGRATION")
    print("=" * 85)
    print("📋 Attack Types Monitored:")
    print("   🔵 UDP Flood Detection (Rule-based + ML)")
    print("   🟡 ICMP Flood Detection (Rule-based + ML + Adaptive PPS Weighting)")
    print("   🟣 SYN Flood Detection (Rule-based + ML + Enhanced Confidence Normalization)")
    print("=" * 85)
    print("🆕 Enhanced Features:")
    print("   ✅ Attack State Tracking (Start/Stop detection)")
    print("   📊 Traffic State Classification (Zero/Low/Normal/High)")
    print("   🔄 Attack Transition Monitoring")
    print("   📈 Continuous Feature Publishing")
    print("   🧠 ML Confidence set to 0 when all attack features are zero")
    print("   🛡️ IPTABLES Integration for Real Packet Blocking")
    print("   📊 Dropped Packet Counting per Protocol")
    print("   🔧 Dynamic Firewall Rule Management")
    print("=" * 85)
    print("📁 JSON Storage Paths:")
    print(f"   📊 Attack Data: {ATTACK_DATA_PATH}")
    print(f"   🔵 UDP Features: {UDP_FEATURES_PATH}")
    print(f"   🟡 ICMP Features: {ICMP_FEATURES_PATH}")
    print(f"   🟣 SYN Features: {SYN_FEATURES_PATH}")
    print(f"   🛡️ Firewall Config: {FIREWALL_ACTION_PATH}")
    print("=" * 85)
    print("🛡️ Firewall Actions Available:")
    print("   🚫 'drop'      - Block all monitored protocols (ICMP, UDP, TCP SYN)")
    print("   ⏱️ 'ratelimit' - Allow 100/sec with burst 20, then drop excess")
    print("   ✅ 'none'      - Allow all traffic (default)")
    print("=" * 85)
    
    try:
        # Check if running as root (required for iptables)
        if os.geteuid() != 0:
            print("❌ ERROR: This script requires root privileges to manage iptables")
            print("💡 Please run with: sudo python3 enhanced_ddos_detector.py")
            exit(1)
        
        # Initialize firewall configuration
        print("🔧 Initializing firewall configuration...")
        initial_action = initialize_firewall_config()
        current_fw_action = initial_action
        
        # Load all ML models (NO TRAINING)
        print("🚀 Loading pre-trained ML models...")
        load_udp_models()
        load_icmp_models()
        load_syn_models()
        
        print("\n📡 Starting Enhanced Unified DDoS Detection...")
        print("   🔍 Monitoring UDP, ICMP, and TCP SYN packets...")
        print("   🚨 Real-time rule-based detection active")
        print("   🤖 ML models loaded (no training required)")
        print("   📊 Attack data will be stored in JSON files")
        print("   🎯 Attack state tracking enabled")
        print("   📈 Traffic state classification active")
        print("   🔧 Updated predictions and confidence logic")
        print("   🛡️ IPTABLES integration active")
        print("   📊 Dropped packet counting enabled")
        print(f"   🔧 Initial firewall action: {initial_action.upper()}")
        print("\n" + "=" * 85)
        
        # Start firewall monitoring thread
        threading.Thread(target=monitor_firewall_changes, daemon=True).start()
        
        # Start analysis thread
        threading.Thread(target=analyze_traffic, daemon=True).start()
        
        # Start packet capture
        print("🎯 Starting packet capture...")
        sniff(prn=detect_threats_and_act, store=0)
        
    except KeyboardInterrupt:
        print("\n\n🎯 ENHANCED UNIFIED DDOS DETECTION SYSTEM STOPPED!")
        print("=" * 85)
        print("📊 Detection Components:")
        print(f"   🔵 UDP Detection: {'Active' if udp_ml_enabled else 'Rule-based only'}")
        print(f"   🟡 ICMP Detection: {'Active' if icmp_ml_enabled else 'Rule-based only'}")
        print(f"   🟣 SYN Detection: {'Active' if syn_ml_enabled else 'Rule-based only'}")
        print(f"   📊 JSON Storage: {ATTACK_DATA_PATH}")
        print(f"   🛡️ Firewall Config: {FIREWALL_ACTION_PATH}")
        
        # Get final dropped packet counts
        final_session_counts = get_current_session_counts()
        final_global_counts = get_global_cumulative_counts()
        
        print("📊 Final Packet Count Summary:")
        print(f"   📊 Final Session Dropped: UDP={final_session_counts['udp']}, ICMP={final_session_counts['icmp']}, TCP={final_session_counts['tcp']}")
        print(f"   📈 Session Total: {final_session_counts['total']}")
        print(f"   🌍 Global Cumulative Dropped: UDP={final_global_counts['udp']}, ICMP={final_global_counts['icmp']}, TCP={final_global_counts['tcp']}")
        print(f"   🌍 Global Total: {final_global_counts['total']}")
        
        # Clean up - restore firewall to allow all
        print("🔄 Cleaning up firewall rules...")
        allow_all_traffic()
        print("✅ Firewall restored to ACCEPT all traffic")
        print("=" * 85)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Ensure you have root privileges and iptables-legacy installed")
        print("💡 Try running with: sudo python3 enhanced_ddos_detector.py")
        
        # Clean up on error
        try:
            print("🔄 Attempting to restore firewall rules...")
            allow_all_traffic()
            print("✅ Firewall restored to ACCEPT all traffic")
        except:
            print("❌ Could not restore firewall rules - please check manually")
            print("💡 Run: sudo iptables-legacy -F FORWARD && sudo iptables-legacy -P FORWARD ACCEPT")