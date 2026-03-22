# 🛡️ Güvenlimi? - Web Güvenlik Tarama Platformu

Selamlar! 👋 Bu proje, web sitelerinin güvenlik açıklarını saniyeler içinde analiz eden ve bunu herkesin kolayca anlayabileceği bir dilde raporlayan açık kaynaklı bir tarama platformudur. Arka planda Google Gemini yapay zekasını kullanıyor.

## 🌟 Neler Yapabiliyor?
- **Anında Analiz:** SSL durumu, HTTP başlıkları, XSS, KVKK, Phishing tespitleri, SQL Injection gibi tam 17 farklı güvenlik kriterini tarar.
- **Kullanıcı Sistemi:** Yeni kayıt olanlara otomatik 10 tarama hakkı mantığıyla çalışır. (İstenirse fiyatlandırma modülü de entegre).
- **Yapay Zeka Raporları:** O karmaşık siber güvenlik terimlerini herkesin anlayacağı bir dilde ve pratik çözüm önerileriyle birlikte sunar.
- **Mavi/Beyaz Şık Tasarım:** Saf HTML/CSS ile yazılmış, hızlı ve modern bir arayüz.

## 🛠️ Kullanılan Teknolojiler
- **Backend:** Node.js, Express.js
- **Veritabanı:** SQLite (Kurulum derdi hiç yok, proje çalışınca kendi kendine oluşuyor)
- **Güvenlik & Auth:** JWT, bcryptjs
- **Yapay Zeka:** `@google/generative-ai` (Gemini 2.5 Flash)
- **Frontend:** HTML, CSS (Vanilla), JS

## 🚀 Nasıl Çalıştırırım?

Projeyi kendi bilgisayarınızda veya sunucunuzda ayağa kaldırmak oldukça basit:

1. **Projeyi indirin ve klasöre girin:**
   ```bash
   git clone https://github.com/KULLANICI_ADINIZ/guvenlimi.git
   cd guvenlimi
   ```

2. **Gerekli paketleri kurun:**
   ```bash
   npm install
   ```

3. **Çevre Değişkenlerini (ENV) ayarlayın:**
   - Proje dizininde `.env` (nokta env) adında bir dosya oluşturun.
   - İçerisine Google AI Studio'dan aldığınız API anahtarını ekleyin:
   ```env
   GEMINI_API_KEY=BURAYA_KENDI_API_ANAHTARINIZI_YAZIN
   JWT_SECRET=istediginiz_gizli_bir_kelime
   PORT=3000
   ```
   *(Eğer API anahtarınız yoksa [aistudio.google.com](https://aistudio.google.com/) adresinden saniyeler içinde ücretsiz alabilirsiniz)*

4. **Sunucuyu başlatın:**
   ```bash
   node server.js
   ```

Artık tarayıcınızdan `http://localhost:3000` adresine giderek projeyi kullanabilirsiniz! Veritabanı dosyası (`database.db`) ilk denemenizde otomatik olarak oluşacaktır.

## 🤝 Katkıda Bulunma
Projeyi geliştirmek isterseniz Pull Request göndermekten çekinmeyin. Hatalı veya eklenebilecek yerleri Issues kısmından bildirebilirsiniz. Her türlü katkıya açık!

Lisans: MIT
