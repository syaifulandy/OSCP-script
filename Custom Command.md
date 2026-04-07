# ⚙️ Custom Commands (Kali Linux)

Kumpulan command custom untuk mempercepat workflow (OSCP / Pentest).

---

## 🚀 webserver

**Deskripsi:** Jalankan HTTP server cepat dari folder aktif

### Setup
```bash
sudo nano /usr/local/bin/webserver
```

### Script
```bash
#!/bin/bash
PORT=${1:-8000}
python3 -m http.server "$PORT"
```

### Permission
```bash
sudo chmod +x /usr/local/bin/webserver
```

### Usage
```bash
webserver 80
```

atau

```bash
webserver
```

### Info
- Default port: **8000**
- Gunakan `sudo` untuk port <1024

---
