#!/usr/bin/env python3
"""
model_egitim.py

Bu betik, NSL-KDD veri kümesi kullanılarak IDS modelinin eğitilmesini sağlar.
Eğitim tamamlandıktan sonra model, model.pkl dosyası olarak kaydedilir.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

# 1. Veri Kümesinin Yüklenmesi
data_file = "NSL-KDD.csv"  # Dosya yolunu ve adını gereksiniminize göre güncelleyin.
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "class"  # Hedef sütun "class" olarak yer almaktadır.
]

try:
    data = pd.read_csv(data_file, header=None, names=columns, sep=",")
    print("Veri kümesi başarıyla yüklendi.")
except Exception as e:
    print(f"Veri kümesi yüklenirken hata: {e}")
    exit(1)

# 2. Veri Kümesindeki Sütunları Kontrol Etme
print("Veri kümesindeki sütunlar:")
print(data.columns)

# 3. Kullanılmayacak Sütunların Kaldırılması
if "service" in data.columns:
    data = data.drop(columns=["service"])

# 4. Gerekli Dönüşümler

# a. protocol_type sütununun sayısal değere dönüştürülmesi (tcp: 0, udp: 1, icmp: 2)
protocol_mapping = {"tcp": 0, "udp": 1, "icmp": 2}
data["protocol_type"] = data["protocol_type"].map(lambda x: protocol_mapping.get(x, 2))

# b. flag sütununun sayısal değere dönüştürülmesi
flag_mapping = {
    "SF": 1,
    "S0": 2,
    "REJ": 3,
    "S1": 4,
    "S2": 5,
    "S3": 6,
    "RSTO": 7,
    "RSTR": 8,
    "OTH": 0
}
data["flag"] = data["flag"].map(lambda x: flag_mapping.get(x, 0))

# c. Hedef sütunun etiketlenmesi: "normal" -> 0, diğerleri (saldırı) -> 1
# Eğer veri kümeniz "label" sütununu içermiyorsa, "class" sütununu kullanmalısınız.
data['target'] = data['class'].apply(lambda x: 0 if x.strip().lower() == "normal" else 1)

# d. Herhangi bir eksik değerin 0 ile doldurulması
data.fillna(0, inplace=True)

# 5. Model Eğitimi İçin Özellik ve Hedef Değerlerin Belirlenmesi
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

X = data[feature_order]
y = data["target"]

# 6. Eğitim ve Test Verisine Bölünme (80% eğitim, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 7. Model Eğitiminin Gerçekleştirilmesi (RandomForestClassifier kullanılarak)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("Model başarıyla eğitildi.")

# 8. Modelin Değerlendirilmesi
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Doğruluk Oranı: {accuracy * 100:.2f}%")
print("Sınıflandırma Raporu:")
print(classification_report(y_test, y_pred))

# 9. Eğitilmiş Modelin model.pkl Dosyası Olarak Kaydedilmesi
with open("model.pkl", "wb") as model_file:
    pickle.dump(model, model_file)
print("Model, model.pkl dosyası olarak kaydedildi.")
