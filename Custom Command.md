## 🚀 webserver (enhanced)

**Deskripsi:** HTTP server + auto generate wget/curl berdasarkan IP interface

└─# sudo nano /usr/local/bin/webserver    

### Script
```bash
#!/bin/bash

PORT=${1:-8000}

echo "[+] Starting web server on port $PORT..."
echo

# Ambil semua interface selain loopback
IPS=$(ip -4 -o addr show | awk '!/ lo / {print $2,$4}')

echo "[+] Available download URLs:"
echo

for i in $IPS; do
    IFACE=$(echo $i | cut -d/ -f1)
    IP=$(echo $i | cut -d/ -f1)
done

# Cara lebih clean
ip -4 -o addr show | awk '!/ lo / {
    split($4,a,"/");
    printf "%s:\n", $2;
    printf "  wget http://%s:'"$PORT"'/filename\n", a[1];
    printf "  curl http://%s:'"$PORT"'/filename\n\n", a[1];
}'

echo "[+] Serving files from: $(pwd)"
echo "----------------------------------------"

python3 -m http.server "$PORT"
```

### Usage
```bash
webserver 80
```

---

## 📌 Output Contoh

```
eth0:
  wget http://192.168.116.128:80/file
  curl http://192.168.116.128:80/file

tun0:
  wget http://192.168.45.195:80/file
  curl http://192.168.45.195:80/file
```
