````markdown
# ⚙️ Custom Command: `webserver`

## 1. Buat Script
```bash
sudo nano /usr/local/bin/webserver
````

## 2. Isi Script

```bash
#!/bin/bash
PORT=${1:-8000}
python3 -m http.server "$PORT"
```

## 3. Permission

```bash
sudo chmod +x /usr/local/bin/webserver
```

---

## 🚀 Cara Pakai

```bash
webserver 80
```

atau

```bash
webserver
```

---

## 📌 Info

* Default port: **8000**
* Port <1024 (misal 80):

```bash
sudo webserver 80
```

```
```
