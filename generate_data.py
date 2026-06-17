import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

def generate_auth_logs(num_records=1000):
    users = ["joao", "maria", "pedro", "ana", "carlos"]
    countries = ["Brazil", "Brazil", "Brazil", "Brazil", "United States", "Portugal"]
    ips_br = [f"200.100.50.{i}" for i in range(1, 20)]
    ips_us = [f"198.51.100.{i}" for i in range(1, 10)]
    ips_pt = [f"203.0.113.{i}" for i in range(1, 5)]
    
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Generate Normal Logs
    for _ in range(num_records):
        user = random.choice(users)
        # Normal behavior: logins during daytime (8h to 18h)
        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        sec = random.randint(0, 59)
        day_offset = random.randint(0, 6)
        
        timestamp = base_time + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=sec)
        
        # João always logs from Brazil
        if user == "joao":
            country = "Brazil"
            ip = random.choice(ips_br)
        else:
            country = random.choice(countries)
            if country == "Brazil":
                ip = random.choice(ips_br)
            elif country == "United States":
                ip = random.choice(ips_us)
            else:
                ip = random.choice(ips_pt)
                
        status = "success" if random.random() > 0.05 else "failed"
        
        data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user": user,
            "ip_address": ip,
            "country": country,
            "status": status,
            "event_type": "login"
        })
        
    # Injecting Anomaly 1: Brute Force followed by Success for João at 3 AM from Europe (Romania)
    anomaly_time = base_time + timedelta(days=3, hours=3, minutes=15)
    ip_anomaly = "82.76.12.45" # Romania IP
    country_anomaly = "Romania"
    
    # 49 Failed attempts
    for i in range(49):
        timestamp = anomaly_time + timedelta(seconds=i * 5)
        data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user": "joao",
            "ip_address": ip_anomaly,
            "country": country_anomaly,
            "status": "failed",
            "event_type": "login"
        })
        
    # 1 Successful attempt
    timestamp = anomaly_time + timedelta(seconds=250)
    data.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "user": "joao",
        "ip_address": ip_anomaly,
        "country": country_anomaly,
        "status": "success",
        "event_type": "login"
    })
    
    # Injecting Anomaly 2: Carlos logging from Portugal at 2 AM (single attempt)
    anomaly_time_2 = base_time + timedelta(days=5, hours=2, minutes=40)
    data.append({
        "timestamp": anomaly_time_2.strftime("%Y-%m-%d %H:%M:%S"),
        "user": "carlos",
        "ip_address": "203.0.113.8",
        "country": "Portugal",
        "status": "success",
        "event_type": "login"
    })

    df = pd.DataFrame(data)
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df.to_csv("auth_logs.csv", index=False)
    print("Generated auth_logs.csv successfully.")

def generate_network_logs(num_records=1200):
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Normal network traffic: high frequency, lower duration, lower bytes
    for _ in range(num_records):
        day_offset = random.randint(0, 6)
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        timestamp = base_time + timedelta(days=day_offset, hours=hour, minutes=minute)
        
        src_ip = f"10.0.0.{random.randint(10, 50)}"
        dest_ip = f"192.168.1.{random.randint(2, 254)}" if random.random() > 0.3 else f"8.8.8.{random.randint(1, 8)}"
        
        # Standard ports
        port = random.choice([80, 443, 53, 22])
        
        # Exponential distribution for realistic bytes/duration
        duration = float(np.random.exponential(scale=5.0)) + 0.1 # average 5 seconds
        bytes_sent = int(np.random.exponential(scale=10000)) + 50
        bytes_received = int(np.random.exponential(scale=50000)) + 100
        
        data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "destination_port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "label": "normal"
        })
        
    # Injecting Anomaly 3: C2 (Command & Control) Beaconing
    # Periodic connections with low bytes but constant duration to a specific external IP
    c2_ip = "185.220.101.5"
    infected_host = "10.0.0.15"
    c2_start_time = base_time + timedelta(days=2)
    
    for i in range(150): # Beaconing every 10 minutes
        timestamp = c2_start_time + timedelta(minutes=10 * i)
        # Small fluctuations to simulate jitter
        duration = float(np.random.normal(loc=15.0, scale=0.5))
        bytes_sent = int(np.random.normal(loc=120, scale=5))
        bytes_received = int(np.random.normal(loc=240, scale=10))
        
        data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": infected_host,
            "destination_ip": c2_ip,
            "destination_port": 4444, # Uncommon port
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "label": "malware_beaconing"
        })
        
    # Injecting Anomaly 4: Data Exfiltration
    # Massive transfer of data to external IP
    exfil_ip = "45.79.12.18"
    exfil_host = "10.0.0.22"
    exfil_time = base_time + timedelta(days=4, hours=14, minutes=30)
    
    for i in range(5):
        timestamp = exfil_time + timedelta(minutes=i * 2)
        duration = float(np.random.normal(loc=120.0, scale=10.0))
        bytes_sent = int(np.random.normal(loc=50_000_000, scale=5_000_000)) # 50 MB
        bytes_received = int(np.random.normal(loc=10_000, scale=1000))
        
        data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": exfil_host,
            "destination_ip": exfil_ip,
            "destination_port": 22, # SFTP
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "label": "data_exfiltration"
        })

    df = pd.DataFrame(data)
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df.to_csv("network_logs.csv", index=False)
    print("Generated network_logs.csv successfully.")

if __name__ == "__main__":
    generate_auth_logs()
    generate_network_logs()
