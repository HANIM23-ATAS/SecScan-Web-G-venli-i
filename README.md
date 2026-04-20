# SecScan - Gelişmiş Web Güvenlik Tarayıcısı

**Öğrenci Bilgileri:**
- **İsim Soyisim:** HANIM ATAŞ
- **Öğrenci No:** 2408410032

---

## Proje Hakkında
SecScan, girilen URL'ler üzerinde 7 farklı güvenlik kontrolünü eşzamanlı (parallel) olarak gerçekleştiren yüksek performanslı bir güvenlik tarama platformudur. Modern web mimarisi standartları baz alınarak, güvenliği ve hızı ön planda tutacak şekilde geliştirilmiştir.

## Temel Özellikler
- **Yüksek Performans:** Go'nun hafif iş parçacıkları (Goroutines) sayesinde tüm tarama modülleri aynı anda çalışır.
- **SSRF Koruması:** Kullanıcı tarafından girilen URL'ler, iç ağ IP adreslerini taramayı engelleyen ve DNS rebinding saldırılarına karşı koruma sağlayan özel bir middleware ile denetlenir.
- **Modern Dashboard:** Next.js ve Tailwind CSS ile hazırlanmış, kullanıcı dostu ve dinamik bir yönetim paneli.
- **Modüler Yapı:** Clean Architecture prensiplerine uygun, kolay genişletilebilir tarayıcı motoru.

## Teknoloji Yığını
- **Backend:** Go (Gin Framework)
- **Frontend:** Next.js 15, Tailwind CSS, Lucide Icons
- **İletişim:** Axios (Client-side polling)
- **Altyapı:** Docker & Docker Compose

## Güvenlik Modülleri
SecScan aşağıdaki 7 kritik kontrolü gerçekleştirir:
1.  **SQLi Tespit:** Veritabanı enjeksiyon zafiyetlerini kontrol eder.
2.  **XSS Tespit:** Reflected XSS açıklarını denetler.
3.  **Security Header Kontrolü:** HSTS, CSP gibi kritik güvenlik başlıklarını analiz eder (A+ Hedefi).
4.  **JWT/Cookie Audit:** Çerez güvenliği ve JWT yapılandırmasını inceler.
5.  **TLS/SSL Yapılandırması:** Sertifika geçerliliği ve protokol güvenliğini kontrol eder.
6.  **Disclosure Kontrolü:** Sunucu sürümü ve hassas bilgi sızıntılarını denetler.
7.  **Port Discovery:** Kritik servislerin açık portlarını (80, 443 vb.) tarar.

## Kurulum ve Çalıştırma

Projeyi çalıştırmak için sisteminizde **Docker** ve **Docker Compose** kurulu olması yeterlidir.

1.  Proje ana dizinine gidin.
2.  Aşağıdaki komutu çalıştırın:
    ```bash
    docker-compose up -d --build
    ```
3.  Servisler ayağa kalktıktan sonra:
    - **Dashboard:** [http://localhost:3000](http://localhost:3000)
    - **Backend API:** [http://localhost:8080](http://localhost:8080) adresinden erişilebilir.

## API Tasarımı

### Tarama Başlatma
- **Endpoint:** `POST /api/v1/scan`
- **Body:** `{"url": "https://example.com"}`
- **Dönüş:** `{"scan_id": "...", "status": "processing"}`

### Rapor Alma
- **Endpoint:** `GET /api/v1/report/:scan_id`
- **Dönüş:** Tüm modüllerin tarama sonuçlarını içeren detaylı JSON objesi.

---
*Bu proje, modern web güvenliği prensipleri doğrultusunda eğitim vizyonuyla hazırlanmıştır.*
