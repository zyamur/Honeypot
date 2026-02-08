# 🛡️ Advanced Mid-Interaction Telnet Honeypot

Bu proje, siber saldırganların ve otomatik botların davranışlarını analiz etmek amacıyla **Python** ile geliştirilmiş, orta etkileşimli (mid-interaction) bir **Telnet Honeypot** uygulamasıdır. 

Sistem, sahte bir Debian terminali (Fake Shell) simüle ederek saldırganın hem kimlik bilgilerini hem de sistem içerisinde yürüttüğü tüm komutları kayıt altına alır.

## ✨ Öne Çıkan Özellikler

* **Mid-Interaction Simülasyonu:** Sadece port dinlemek yerine, saldırganla etkileşime giren sahte bir Linux shell ortamı sunar.
* **İlişkisel Veri Tabanı (SQLite):** Saldırı oturumlarını (`attacks`) ve bu oturumlara bağlı komut geçmişini (`command_history`) "Foreign Key" ilişkisiyle profesyonelce saklar.
* **Protokol Optimizasyonu:** * **CRLF Desteği:** Telnet standartlarına uygun terminal hizalaması.
    * **Echo Yönetimi:** Karakterlerin çift basılmasını engelleyen akıllı yankı kontrolü.
    * **Dinamik Backspace:** Terminal üzerinden karakter silme işleminin simülasyonu.
* **Veri Temizleme:** Yazdırılamayan karakterlerin filtrelenmesi (BLOB önleme).

## 📊 Veri Tabanı Mimarisi

Sistem verileri iki ana tabloda depolar:
1.  **attacks:** IP adresi, giriş zamanı, kullanıcı adı ve parola.
2.  **command_history:** Her saldırı oturumuyla eşleşen, saldırganın yürüttüğü komutlar ve zaman damgaları.

## 🛠️ Kurulum ve Çalıştırma  Aşamaları
  python honeypot.py
  telnet localhost 5000
   
