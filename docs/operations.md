# ultraSpoof — راه‌اندازی عملیاتی

## پیش‌نیازها

- Ubuntu 24.04 x86_64 (روی سرور ترکیه و در صورت تمایل ایران)
- Go 1.22+ (فقط برای کامپایل)
- Xray روی ایران (کلاینت) و ترکیه (سرور) برای تونل VLESS/SOCKS
- روی سرور ترکیه برای ارسال raw/spoof: معمولاً `CAP_NET_RAW` (مثلاً `setcap`) یا اجرای موقت با کاربر روت طبق سیاست شما

## نصب Xray (نمونه — ترکیه)

باینری رسمی را از مخزن پروژهٔ Xray بگیرید و سرویس systemd بسازید. یک inbound VLESS و یک outbound `freedom` برای دسترسی به اینترنت کافی است. پورت دقیق را با `server.listen.tcp` و `client.remote` در ultraSpoof هم‌راستا کنید (مثلاً 9443).

روی **ایران**، Xray را طوری تنظیم کنید که یک **SOCKS محلی** (مثلاً `127.0.0.1:10808`) به همان inbound ترکیه وصل شود. سپس `client.upstream_socks` در `client.yaml` همان آدرس باشد تا ترافیک کنترل ultraSpoof از مسیر VLESS عبور کند.

## زنجیرهٔ پورت‌ها

1. اپلیکیشن‌ها به `client.listen.socks` (مثلاً `127.0.0.1:1080`) وصل می‌شوند.
2. ultraSpoof از طریق `upstream_socks` به سرور ترکیه روی آدرس `remote` (مثلاً `IP_TR:9443`) متصل می‌شود.
3. روی ترکیه، ultraSpoof روی `server.listen.tcp` گوش می‌دهد (همان 9443 اگر مستقیم expose کنید، یا پشت reverse proxy — در حالت ساده مستقیم روی IP عمومی).
4. دانلود رمزنگاری‌شده روی UDP به `iran_ip:iran_udp_port` با سورس spoof شده (`spoof_source_ip`) ارسال می‌شود.
5. روی ایران، `client.download.listen_udp` باید همان پورت را باز کند و فیلتر ورودی برای IP اسپوف را در فایروال رعایت کنید.

## قابلیت اجرای spoof (ترکیه)

```bash
sudo setcap cap_net_raw+eip /usr/local/bin/ultraSpoof
```

اگر `interface` در `server.yaml` خالی است ولی نیاز به bind به اینترفیس خاص دارید، مقدار آن را پر کنید (مثلاً `eth0`).

## تست تحویل UDP spoof (ایران)

روی سرور ایران:

```bash
sudo tcpdump -n -i any udp and host 194.225.101.22
```

باید بسته‌های UDP ورودی از آن آدرس (در صورت صحت مسیر شبکه) دیده شوند. اگر چیزی نمی‌رسد، قبل از اتکا به ultraSpoof، مسیریابی و فیلترینگ را بررسی کنید.

## فرمت کانفیگ

فایل‌ها باید **JSON معتبر** باشند (می‌توانید نام فایل را `client.yaml` / `server.yaml` بگذارید؛ محتوا باید JSON باشد تا `encoding/json` آن را بخواند).

## کامپایل

```bash
cd /path/to/ultraSpoof
chmod +x scripts/build_linux_amd64.sh
./scripts/build_linux_amd64.sh
```

کراس‌کامپایل از ویندوز با Git Bash یا PowerShell:

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags="-s -w" -o ultraSpoof ./cmd/ultraSpoof
```

## اجرا

```bash
ultraSpoof -c /etc/ultraspoof/client.yaml
ultraSpoof -c /etc/ultraspoof/server.yaml
```
