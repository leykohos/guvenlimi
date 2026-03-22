require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const db = new Database('database.db');
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Database Setup ───────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    credits INTEGER DEFAULT 10,
    last_scan_date TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    package_name TEXT NOT NULL,
    credits_added INTEGER NOT NULL,
    amount_tl INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token gerekli' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Geçersiz token' });
  }
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Tüm alanlar zorunlu' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(400).json({ error: 'Bu e-posta zaten kayıtlı' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name, email, hash);
  const token = jwt.sign({ userId: result.lastInsertRowid }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, message: 'Kayıt başarılı' });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'E-posta ve şifre gerekli' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'E-posta veya şifre hatalı' });

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, message: 'Giriş başarılı' });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, name, email, credits, last_scan_date, created_at FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

  const today = new Date().toISOString().split('T')[0];
  const canScan = user.credits > 0 && user.last_scan_date !== today;
  const scans = db.prepare('SELECT id, url, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 10').all(req.userId);

  res.json({ ...user, canScan, scans });
});

// ─── Scan Route ───────────────────────────────────────────────────────────────
app.post('/api/scan', authMiddleware, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL gerekli' });

  const today = new Date().toISOString().split('T')[0];
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);

  // Check daily limit
  if (user.last_scan_date === today) {
    return res.status(429).json({
      error: 'Günlük tarama hakkınızı kullandınız',
      canPurchase: true
    });
  }

  // Check credits
  if (user.credits <= 0) {
    return res.status(429).json({
      error: 'Tarama hakkınız kalmadı. Lütfen satın alın.',
      canPurchase: true
    });
  }

  // Validate URL format
  let targetUrl = url;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

    const prompt = `
Sen bir web güvenlik uzmanısın. Aşağıdaki web sitesi URL'sini güvenlik açısından analiz et.
URL: ${targetUrl}

Lütfen aşağıdaki konuları değerlendir ve JSON formatında yanıt ver:

{
  "score": <0-100 arası güvenlik skoru>,
  "domain": "<alan adı>",
  "summary": "<kısa genel değerlendirme>",
  "checks": [
    {
      "category": "<kontrol adı>",
      "status": "<güvenli|riskli|uyarı>",
      "description": "<açıklama>",
      "recommendation": "<öneri>"
    }
  ],
  "criticalIssues": <kritik sorun sayısı>,
  "warnings": <uyarı sayısı>,
  "passed": <geçen kontrol sayısı>
}

Kontrol edilecek konular:
1. HTTPS Kullanımı - Site HTTPS mi kullanıyor? HTTP mi?
2. SSL/TLS Sertifikası - Geçerli sertifika var mı?
3. HTTP Güvenlik Başlıkları - CSP, HSTS, X-Frame-Options, X-Content-Type-Options
4. Açık Yönlendirme Riski - URL'de açık yönlendirme parametreleri var mı?
5. XSS Koruması - X-XSS-Protection başlığı
6. Clickjacking Koruması - X-Frame-Options başlığı
7. MIME Type Saldırıları - X-Content-Type-Options başlığı
8. SQL Injection Belirtileri - URL'de şüpheli parametreler
9. Robots.txt ve Sitemap - Gizli dosyalara erişim
10. Alan Adı Güvenilirliği - Alan adı yaşı ve güvenilirliği
11. Hassas Veri Sızıntısı (Data Leakage) - HTML/JS içinde API anahtarları, şifreler, yorum satırları.
12. Kimlik Avı (Phishing) ve Marka Taklidi - Alan adının tehlikeli olup olmadığı (typo-squatting).
13. KVKK ve GDPR Uyumluluğu - Çerez uyarıları, gizlilik politikası, izinsiz takip betikleri.
14. Dışa Açık Admin Paneli - wp-admin, phpmyadmin gibi panellerin açık olma riski.
15. Zayıf Yazılım Sürümleri - Kullanılan kütüphanelerin (jQuery, PHP vb.) zafiyet barındıran eski versiyonları.
16. E-posta Sahteciliği (Spoofing) - Alan adının spam/oltalama mailleri için kullanılabilme ihtimali.
17. İzin Politikaları (Permissions-Policy) - Kamera, mikrofon veya konum yetkisi kullanım riskleri.

Gerçekçi ve eğitici bir analiz yap. Sadece JSON döndür, başka bir şey ekleme.
`;

    const result = await model.generateContent(prompt);
    const text = result.response.text();

    // Parse JSON from response
    let reportData;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      reportData = JSON.parse(jsonMatch[0]);
    } catch {
      reportData = {
        score: 50,
        domain: new URL(targetUrl).hostname,
        summary: 'Analiz tamamlandı. Ayrıntılar için kontrolleri inceleyiniz.',
        checks: [],
        criticalIssues: 0,
        warnings: 0,
        passed: 0
      };
    }

    // Deduct credit and update last scan date
    db.prepare('UPDATE users SET credits = credits - 1, last_scan_date = ? WHERE id = ?').run(today, req.userId);

    // Save scan to db
    const scanResult = db.prepare('INSERT INTO scans (user_id, url, report_json) VALUES (?, ?, ?)').run(
      req.userId, targetUrl, JSON.stringify(reportData)
    );

    res.json({ scanId: scanResult.lastInsertRowid, report: reportData });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ error: 'Tarama sırasında hata oluştu: ' + err.message });
  }
});

// ─── Get Scan Report ──────────────────────────────────────────────────────────
app.get('/api/scan/:id', authMiddleware, (req, res) => {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!scan) return res.status(404).json({ error: 'Rapor bulunamadı' });
  res.json({ ...scan, report: JSON.parse(scan.report_json) });
});

// ─── Purchase Route ───────────────────────────────────────────────────────────
const PACKAGES = {
  starter:    { name: 'Başlangıç',  credits: 10,  price: 100 },
  pro:        { name: 'Pro',        credits: 30,  price: 250 },
  enterprise: { name: 'Kurumsal',   credits: 100, price: 700 }
};

app.post('/api/purchase', authMiddleware, (req, res) => {
  const { packageId, cardNumber, cardName, expiry, cvv } = req.body;
  const pkg = PACKAGES[packageId];
  if (!pkg) return res.status(400).json({ error: 'Geçersiz paket' });
  if (!cardNumber || !cardName || !expiry || !cvv)
    return res.status(400).json({ error: 'Kart bilgileri eksik' });

  // Mock payment - always succeeds
  db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(pkg.credits, req.userId);
  db.prepare('INSERT INTO purchases (user_id, package_name, credits_added, amount_tl) VALUES (?, ?, ?, ?)').run(
    req.userId, pkg.name, pkg.credits, pkg.price
  );

  res.json({
    success: true,
    message: `${pkg.credits} tarama hakkı hesabınıza eklendi!`,
    creditsAdded: pkg.credits
  });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡️  Güvenlimi? sunucusu çalışıyor: http://localhost:${PORT}\n`);
});
