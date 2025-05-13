#!/usr/bin/env python3
"""
ids.py

Bu kod, canlı ağ trafiğini izleyip NSL-KDD modeliyle analiz eder.
Saldırı tespitinde, paketin IP katmanı mevcutsa iptables komutuyla IP'yi engeller.
"""

import pickle            # Model dosyasını yüklemek için.
import pandas as pd      # Veri çerçevesi (DataFrame) oluşturmak için.
import subprocess      # iptables komutlarını çalıştırmak için.
from scapy.all import sniff, IP, TCP, UDP  # Paket yakalamak için.
import time              # Zaman kontrolleri için.

# Global değişkenler: normal trafik sayısı ve son özetin yazdırıldığı zaman.
normal_counter = 0
last_print_time = time.time()

# 1. Model Yükleme
try:
    with open("model.pkl", "rb") as model_file:
        model = pickle.load(model_file)
    print("Model başarıyla yüklendi.")
except Exception as e:
    print(f"Model yüklenirken hata: {e}")
    exit(1)

def extract_features(packet):
    """
    Paketi, modelin beklediği özellik formatına dönüştürür.
    NSL-KDD veri kümesinde kullanılan özellikler doğrultusunda örnek değerler üretilmiştir.
    """
    features = {}
    features["duration"] = 0

    if packet.haslayer(TCP):
        features["protocol_type"] = 0       # 0 = TCP
        features["src_bytes"] = len(packet[TCP].payload)
        features["dst_bytes"] = 0
        flags = packet[TCP].flags
        features["flag"] = int(flags)
    elif packet.haslayer(UDP):
        features["protocol_type"] = 1       # 1 = UDP
        features["src_bytes"] = len(packet[UDP].payload)
        features["dst_bytes"] = 0
        features["flag"] = 0
    else:
        features["protocol_type"] = 2       # Diğer protokoller
        features["src_bytes"] = 0
        features["dst_bytes"] = 0
        features["flag"] = 0

    # Diğer sabit (dummy) özellikler:
    dummy_features = {
        "land": 0, "wrong_fragment": 0, "urgent": 0, "hot": 0, "num_failed_logins": 0,
        "logged_in": 1, "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0, "count": 0,
        "srv_count": 0, "serror_rate": 0, "srv_serror_rate": 0, "rerror_rate": 0,
        "srv_rerror_rate": 0, "same_srv_rate": 0, "diff_srv_rate": 0, "srv_diff_host_rate": 0,
        "dst_host_count": 0, "dst_host_srv_count": 0, "dst_host_same_srv_rate": 0,
        "dst_host_diff_srv_rate": 0, "dst_host_same_src_port_rate": 0,
        "dst_host_srv_diff_host_rate": 0, "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0, "dst_host_rerror_rate": 0, "dst_host_srv_rerror_rate": 0
    }
    features.update(dummy_features)

    feature_order = [
        "duration", "protocol_type", "src_bytes", "dst_bytes", "flag",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
        "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
    ]
    feature_vector = [features[col] for col in feature_order]
    return feature_vector

def process_packet(packet):
    """
    Her yakalanan paketi işleyip, model üzerinden tahmin yapar.
    Saldırı tespit edildiğinde, paketin IP bilgisi varsa iptables kuralıyla IP'yi engeller.
    Normal trafik için özet bilgi vermek üzere global sayaç kullanılır.
    """
    global normal_counter, last_print_time
    try:
        features = extract_features(packet)
        cols = [
            "duration", "protocol_type", "src_bytes", "dst_bytes", "flag",
            "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
            "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
            "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]
        df = pd.DataFrame([features], columns=cols)

        # Model tahmini: 0 -> normal, 1 -> saldırı
        prediction = model.predict(df)
        if prediction[0] == 1:
            if packet.haslayer(IP):
                attacker_ip = packet[IP].src
                block_ip(attacker_ip)
                print(f"Saldırı tespit edildi: {attacker_ip} engellendi.")
            else:
                print("Saldırı tespit edildi; ancak IP bilgisi elde edilemedi.")
        else:
            # Sadece normal trafik için sayaç artışı ve belirli aralıkta özet çıktı verilir.
            normal_counter += 1
            if time.time() - last_print_time >= 5:  # Her 5 saniyede bir özet çıktı verir.
                print(f"Normal trafik tespit edildi. Son 5 saniyede {normal_counter} normal paket işlendi.")
                normal_counter = 0
                last_print_time = time.time()
    except Exception as e:
        print(f"Hata: {e}")

def block_ip(ip):
    """
    Belirtilen IP adresine iptables kuralı ekler.
    Bu komut Linux ortamında çalışır ve 'sudo' yetkisi gerektirir.
    """
    try:
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(command, check=True)
        print(f"{ip} için iptables kuralı başarıyla eklendi.")
    except subprocess.CalledProcessError as err:
        print(f"iptables kuralı eklenirken hata: {err}")

def start_sniffing():
    """
    Yalnızca IP paketleri filtrelenerek canlı trafik izlenir.
    """
    print("Ağ paketi izleme başlatıldı...")
    # Sadece IP paketlerini yakalamak için filtre eklenmiştir.
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
