# ultraSpoof

> یک ابزار پروکسی دوتکه (کلاینت + سرور) که آپلود را از طریق یک تونل معمولی (مثلاً Xray/VLESS) عبور می‌دهد و دانلود را با **IP منبع جعلی (spoofed)** روی UDP مستقیم به ایران تزریق می‌کند تا مسیر برگشت سریع‌تر و کم‌هزینه‌تر باشد.

این README را طوری نوشته‌ایم که حتی اگر با Go یا شبکه آشنایی زیادی ندارید، بتوانید مرحله به مرحله همه چیز را راه بیندازید. اگر جایی گیر کردید، بخش «رفع اشکال» انتهای متن را ببینید.

---

## فهرست مطالب

- [ultraSpoof چیست و چه می‌کند؟](#ultraspoof-چیست-و-چه-می‌کند)
- [معماری در یک نگاه](#معماری-در-یک-نگاه)
- [پیش‌نیازها](#پیش‌نیازها)
- [ساختار پروژه](#ساختار-پروژه)
- [کامپایل (ساخت باینری)](#کامپایل-ساخت-باینری)
- [گام ۱: آماده‌سازی سرور ترکیه](#گام-۱-آماده‌سازی-سرور-ترکیه)
- [حالت `udp_relay` و رلهٔ فقط-NAT روی واسط](#udp-relay-gateway)
- [گام ۲: آماده‌سازی سرور ایران](#گام-۲-آماده‌سازی-سرور-ایران)
- [گام ۳: ساخت فایل‌های کانفیگ](#گام-۳-ساخت-فایل‌های-کانفیگ)
- [گام ۴: اجرای سرویس‌ها](#گام-۴-اجرای-سرویس‌ها)
- [گام ۵: تست اتصال](#گام-۵-تست-اتصال)
- [توضیح کامل فیلدهای کانفیگ](#توضیح-کامل-فیلدهای-کانفیگ)
- [تنظیمات پیشرفتهٔ عملکرد (Workers و بافرها)](#تنظیمات-پیشرفتهٔ-عملکرد-workers-و-بافرها)
- [حالت Aggressive (بدون رمزنگاری، حداکثر سرعت)](#حالت-aggressive-بدون-رمزنگاری-حداکثر-سرعت)
- [پروفایل‌های آمادهٔ ترافیک (۱۰ / ۵۰ / ۲۰۰ / ۵۰۰ کاربر)](#پروفایل‌های-آمادهٔ-ترافیک-۱۰--۵۰--۲۰۰--۵۰۰-کاربر)
- [Tuning سطح کرنل (sysctl / ulimit / NIC)](#tuning-سطح-کرنل-sysctl--ulimit--nic)
- [اجرا به‌صورت systemd](#اجرا-به‌صورت-systemd)
- [لاگ‌گیری و عیب‌یابی](#لاگ‌گیری-و-عیب‌یابی)
- [رفع اشکال (Troubleshooting)](#رفع-اشکال-troubleshooting)
- [جزییات فنی پروتکل](#جزییات-فنی-پروتکل)
- [ملاحظات امنیتی و قانونی](#ملاحظات-امنیتی-و-قانونی)

---

## ultraSpoof چیست و چه می‌کند؟

فرض کنید در ایران هستید و می‌خواهید ترافیک مرورگر/اپ را از یک سرور خارج (ترکیه) عبور دهید. معمولاً برای این کار از یک تونل کامل مثل Xray/VLESS استفاده می‌شود و **همهٔ ترافیک (آپلود + دانلود)** از مسیر تونل برمی‌گردد. این مسیر گاهی کند می‌شود، چون پهنای‌باند بین‌الملل محدود است.

ایدهٔ `ultraSpoof` این است که مسیر رفت و برگشت را تفکیک کند:

- **آپلود (ایران → ترکیه)**: فریم‌های کنترل + دادهٔ آپلود از طریق یک تونل موجود (مثلاً Xray/VLESS با یک SOCKS محلی در ایران) به باینری سرور در ترکیه می‌روند. این بخش «سالم و رمزنگاری‌شده» است.
- **دانلود (ترکیه → ایران)**: سرور ترکیه دادهٔ دانلود را در بسته‌های UDP رمزنگاری‌شده می‌گذارد و با یک **IP منبع جعلی داخلی ایران** مستقیماً به IP عمومی سرور ایران شما می‌فرستد. این بسته‌ها از مسیر پیشنهادی شبکه می‌آیند (نه از داخل تونل)، و برای کاربر نهایی مثل همان ترافیک دانلود تونل عمل می‌کنند.

نتیجه: **پروکسی محلی روی دستگاه کاربر (SOCKS5 روی `127.0.0.1:1080`)**، ولی دانلود سریع‌تر.

> مهم: این ابزار برای یک سناریوی خاص طراحی شده و به Raw Socket در سرور لینوکس و کنترل روی هر دو سمت (ایران و ترکیه) نیاز دارد.

---

## معماری در یک نگاه

```
                     ایران                                        ترکیه
  ┌──────────────────────────────────────┐         ┌──────────────────────────────────┐
  │  اپ کاربر (مرورگر و ...)             │         │                                  │
  │          │                            │         │                                  │
  │          ▼ SOCKS5 / HTTP CONNECT      │         │                                  │
  │  ultraSpoof (mode=client)             │         │   ultraSpoof (mode=server)       │
  │   - listen.socks   127.0.0.1:1080     │         │    - listen.tcp  0.0.0.0:9443    │
  │   - upstream_socks 127.0.0.1:10808 ───┼──VLESS──┼──▶ Xray inbound                  │
  │     (Xray client محلی در ایران)       │ tunnel  │         │                        │
  │                                        │         │         ▼                        │
  │                                        │         │   handleConn → dial(target)      │
  │                                        │         │                                  │
  │                                        │         │   target (مثلاً google.com:443)  │
  │                                        │         │         │                        │
  │                                        │         │         ▼                        │
  │  listen_udp   0.0.0.0:9444  ◀──raw UDP,│src=spoof│── spoof.SendUDP (CAP_NET_RAW)    │
  │  (filter source IP = spoof_source_ip) │         │                                  │
  │          │                            │         │                                  │
  │          ▼ unseal + reassemble        │         │                                  │
  │   برگشت به اپ کاربر از همان SOCKS5   │         │                                  │
  └──────────────────────────────────────┘         └──────────────────────────────────┘
```

به زبان ساده:

1. اپ کاربر به پروکسی محلی `ultraSpoof` وصل می‌شود.
2. `ultraSpoof` ایران، مسیر کنترل و آپلود را از تونل Xray به سرور ترکیه می‌فرستد.
3. سرور ترکیه به سایت مقصد وصل می‌شود.
4. دانلود را به‌صورت قطعات UDP رمزنگاری‌شده، با `IP منبع جعلی` مستقیماً به IP ایران می‌فرستد.
5. `ultraSpoof` ایران این UDPها را می‌گیرد، رمزگشایی و مرتب می‌کند و به اپ کاربر تحویل می‌دهد.

---

## پیش‌نیازها

### سرور ترکیه (Server)

- Ubuntu 22.04 / 24.04 روی x86_64 (لینوکس الزامی است چون فقط لینوکس `raw socket` دارد).
- IP عمومی ثابت.
- امکان ارسال raw packet (نیاز به `CAP_NET_RAW` یا اجرا با root).
- یک Xray (یا هر پروکسی مشابه) با inbound روی همان پورتی که `server.listen.tcp` گوش می‌دهد، اگر می‌خواهید ترافیک کنترل را داخل VLESS بگذارید.
- Go 1.22 به بالا، **فقط در صورتی که خودتان کامپایل می‌کنید**. در غیر این صورت فقط باینری آمادهٔ `ultraSpoof` کافی است.

### سرور/دستگاه ایران (Client)

- Ubuntu (ترجیحاً)، Windows هم برای حالت کلاینت کار می‌کند ولی برای تست UDP ورودی باید فایروال و NIC اجازه دهند.
- IP عمومی ثابت (همان IP که در `server.download.iran_ip` گذاشته‌اید).
- امکان باز کردن یک پورت UDP عمومی (مثلاً `9444`).
- Xray محلی که یک خروجی SOCKS روی `127.0.0.1:10808` به inbound ترکیه می‌فرستد (برای مسیر کنترل).

### عمومی

- یک رمز مشترک (PSK) که در هر دو طرف یکسان باشد. می‌توانید با دستور زیر بسازید:

  ```bash
  openssl rand -base64 32
  ```

---

## ساختار پروژه

```
ir/
├─ cmd/ultraSpoof/main.go         نقطهٔ ورود باینری
├─ internal/
│  ├─ applog/                     لاگر قابل‌تنظیم (off / info / debug)
│  ├─ client/                     پیاده‌سازی حالت کلاینت (SOCKS5, HTTP CONNECT, UDP hub, ...)
│  ├─ config/                     خواندن/اعتبارسنجی JSON کانفیگ
│  ├─ crypto/                     مشتق‌کنندهٔ کلید AES-GCM برای UDP
│  ├─ protocol/                   فریم‌های TCP کنترل + فریم‌های UDP دانلود
│  ├─ server/                     حالت سرور (dial به مقصد، spoof UDP و/یا udp_relay)
│  └─ spoof/                      ساخت raw packet با IP منبع جعلی (فقط لینوکس)
├─ scripts/
│  ├─ build_linux_amd64.sh              بیلد لینوکس amd64
│  ├─ build_windows_amd64.bat           بیلد ویندوز + کراس‌کامپایل لینوکس amd64
│  ├─ linux_relay_tcp_dnat.sh             رلهٔ TCP کنترل (nftables) روی واسط
│  ├─ linux_relay_udp_snat_turkey.sh      رلهٔ UDP دانلود + SNAT به spoof (nftables)
│  └─ ...
├─ client.yaml                    نمونهٔ کانفیگ کلاینت (JSON)
├─ server.yaml                    نمونهٔ کانفیگ سرور (JSON)
├─ ultraSpoof                     باینری آمادهٔ لینوکس (در صورت وجود)
└─ ultraSpoof.exe                 باینری آمادهٔ ویندوز (در صورت وجود)
```

> توجه: با وجود پسوند `.yaml`، محتوای فایل‌های کانفیگ **JSON معتبر** است. این پسوند فقط برای راحتی ویرایشگر است.

---

## کامپایل (ساخت باینری)

اگر فایل `ultraSpoof` (لینوکس) و `ultraSpoof.exe` (ویندوز) از قبل در کنار پروژه هست، می‌توانید این گام را رد کنید و یک‌راست به «گام ۱» بروید.

### روش ۱: بیلد روی خود لینوکس

```bash
cd /path/to/ir
chmod +x scripts/build_linux_amd64.sh
./scripts/build_linux_amd64.sh
```

خروجی: `./ultraSpoof`

### روش ۲: کراس‌کامپایل از ویندوز (PowerShell)

```powershell
cd C:\Users\line98\Desktop\ir
.\scripts\build_windows_amd64.bat
```

این اسکریپت هم `ultraSpoof.exe` (ویندوز) و هم `ultraSpoof` (لینوکس) را می‌سازد.

### روش ۳: دستی

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags="-s -w" -o ultraSpoof ./cmd/ultraSpoof
```

---

## گام ۱: آماده‌سازی سرور ترکیه

### ۱-۱) آپلود باینری

فایل `ultraSpoof` (نسخهٔ لینوکس) را به سرور ترکیه کپی کنید (مثلاً `scp`):

```bash
scp ultraSpoof root@TURKEY_PUBLIC_IP:/usr/local/bin/ultraSpoof
ssh root@TURKEY_PUBLIC_IP "chmod +x /usr/local/bin/ultraSpoof"
```

### ۱-۲) اجازهٔ ارسال raw packet

برای اینکه برنامه بدون root هم بتواند بسته‌های UDP با IP منبع جعلی بفرستد، به آن `CAP_NET_RAW` بدهید:

```bash
sudo setcap cap_net_raw+eip /usr/local/bin/ultraSpoof
```

اگر اجرای مستقیم با root مشکلی ندارد، این گام اختیاری است.

### ۱-۳) Xray روی ترکیه (اختیاری ولی توصیه‌شده)

یک inbound ساده VLESS روی ترکیه راه بیندازید که از بیرون قابل اتصال باشد. مقصد outbound می‌تواند `freedom` باشد. **مهم نیست Xray روی چه پورتی است**؛ اتصال کنترل ultraSpoof مستقیم به پورت `server.listen.tcp` (مثلاً `9443`) می‌رود.

> اگر نمی‌خواهید Xray را درگیر کنید، روی سرور ایران می‌توانید `upstream_socks` را به یک SOCKS خنثی یا ساده‌تر وصل کنید، اما مدل اصلی فرض می‌کند ترافیک کنترل از داخل یک تونل VLESS عبور می‌کند.

### ۱-۴) باز کردن پورت TCP در فایروال

پورت `server.listen.tcp` (مثلاً `9443/tcp`) باید از ایران قابل اتصال باشد:

```bash
sudo ufw allow 9443/tcp
```

### ۱-۵) باز بودن خروجی UDP

سرور ترکیه باید بتواند به IP ایران شما روی `iran_udp_port` (مثلاً `9444/udp`) بستهٔ UDP بفرستد. معمولاً خروجی ISP آزاد است، ولی اگر فایروال محدودکننده دارید، مطمئن شوید بسته‌های raw از `OUTPUT` عبور می‌کنند.

### ۱-۶) اگر سرور دانلود روی ترکیه نیست (اختیاری)

اگر باینری سرور روی ماشین دیگری است (مثلاً آلمان) و روی **سرور واسط** (مثلاً ترکیه) فقط اجازهٔ `nftables`/NAT دارید و نمی‌خواهید `ultraSpoof` نصب کنید، از بخش **[حالت udp_relay و رلهٔ فقط-NAT روی واسط](#udp-relay-gateway)** استفاده کنید: همانجا اسکریپت‌ها و پیش‌نیاز ماژول‌های کرنل توضیح داده شده‌اند.

---

<a id="udp-relay-gateway"></a>

## حالت udp_relay و رلهٔ فقط-NAT روی واسط

در مدل پیش‌فرض، سروری که `mode=server` دارد با **raw socket** بستهٔ UDP دانلود را مستقیماً به `iran_ip:iran_udp_port` می‌فرستد و در IP لایهٔ شبکه **منبع را جعل** می‌کند (`spoof_source_ip`). اگر آن سرور **نمی‌تواند** raw بفرستد (یا نمی‌خواهید روی آن `CAP_NET_RAW` بدهید)، می‌توانید بسته‌ها را **اول با UDP معمولی** به یک **سرور واسط** بفرستید؛ واسط فقط با **DNAT + SNAT** (nftables) همان payload را به ایران برساند و مبدأ را به `spoof_source_ip` تغییر دهد. کلاینت ایران تغییری نمی‌کند.

**جریان خلاصه:**

1. **TCP کنترل**: اگر کلاینت به IP واسط وصل می‌شود ولی سرور پشت NAT است، از `scripts/linux_relay_tcp_dnat.sh` روی واسط استفاده کنید (DNAT + MASQUERADE به ماشین سرور واقعی).
2. **UDP دانلود**: در `server.yaml` مقدار `download.udp_relay` را بگذارید، مثلاً `"IP_واسط:9450"`. سرور دانلود دیگر raw spoof روی خودش انجام نمی‌دهد و به این آدرس **UDP معمولی** می‌فرستد. روی واسط `scripts/linux_relay_udp_snat_turkey.sh` را با همان پورت رله و همان `iran_ip` / `iran_udp_port` / `spoof_source_ip` اجرا کنید.

فیلدهای `iran_ip`، `iran_udp_port` و `spoof_source_ip` باید همچنان با `client.yaml` یکسان باشند؛ `udp_relay` فقط **مسیر اولیهٔ ارسال** را به واسط می‌برد.

### پیش‌نیاز کرنل و «ماژول tun»

- برای اسکریپت‌های رله به **nftables** (پکیج `nftables`) و پشتیبانی کرنل از **`nf_tables`** / NAT معمولاً روی VPS آماده است. **فورواردینگ IPv4** را روشن کنید: `net.ipv4.ip_forward=1`.
- **ماژول کرنل `tun` (TUN/TAP)** برای `ultraSpoof` و این اسکریپت‌های NAT **لازم نیست**؛ این پروژه رابط TUN نمی‌سازد. فقط اگر جداگانه VPN یا ابزاری دارید که واقعاً `/dev/net/tun` می‌خواهد، آن‌وقت `tun` مطرح است.
- اگر بعد از نصب `nftables` جدول اضافه نمی‌شود، روی سیستم‌های خیلی مینیمال گاهی لازم است ماژول‌های `nf_tables` / `nf_nat` بارگذاری شوند (بسته به توزیع و کرنل؛ معمولاً با بستهٔ `nftables` و ریبوت یک‌بار حل می‌شود).

---

## گام ۲: آماده‌سازی سرور ایران

### ۲-۱) آپلود باینری

```bash
scp ultraSpoof root@IRAN_PUBLIC_IP:/usr/local/bin/ultraSpoof
ssh root@IRAN_PUBLIC_IP "chmod +x /usr/local/bin/ultraSpoof"
```

### ۲-۲) باز کردن پورت UDP ورودی

پورتی که در `client.download.listen_udp` گذاشته‌اید (مثلاً `9444/udp`) باید روی IP عمومی ایران باز باشد:

```bash
sudo ufw allow 9444/udp
```

### ۲-۳) Xray محلی ایران (برای مسیر کنترل)

Xray را طوری تنظیم کنید که یک **SOCKS inbound محلی** روی `127.0.0.1:10808` داشته باشد و outbound آن به inbound ترکیه وصل باشد (VLESS). این همان SOCKS ای است که `client.upstream_socks` به آن اشاره می‌کند.

ایدهٔ کلی config Xray سمت ایران (خلاصه):

```json
{
  "inbounds": [
    { "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
      "settings": { "udp": false, "auth": "noauth" } }
  ],
  "outbounds": [
    { "protocol": "vless", "settings": { "vnext": [
      { "address": "TURKEY_PUBLIC_IP", "port": 443, "users": [ { "id": "UUID", "encryption": "none" } ] }
    ] }, "streamSettings": { "network": "tcp", "security": "tls" } }
  ]
}
```

### ۲-۴) توجه به فیلترینگ ورودی UDP

روی سرور ایران، بسته‌هایی که از ترکیه با IP منبع جعلی (`spoof_source_ip`) می‌آیند باید توسط هسته تحویل داده شوند. اگر `rp_filter` سخت‌گیرانه روشن است ممکن است آن‌ها را drop کند. در صورت لزوم:

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
```

(قبل از تغییر در production، این تنظیمات را با تیم شبکه/هاستینگ چک کنید.)

---

## گام ۳: ساخت فایل‌های کانفیگ

### ۳-۱) کانفیگ سرور (ترکیه) — `server.yaml`

```json
{
  "mode": "server",
  "psk": "dGVzdC1wYXNzd29yZC0zMi1ieXRlcy1rZXkhISE=",
  "log_level": "info",
  "server": {
    "listen": {
      "tcp": "0.0.0.0:9443"
    },
    "download": {
      "iran_ip": "92.242.220.190",
      "iran_udp_port": 9444,
      "spoof_source_ip": "194.225.101.22",
      "spoof_udp_source_port": 0,
      "interface": "",
      "max_chunk_size": 1200
    },
    "protocol_version": 1
  }
}
```

برای مسیر **[udp_relay](#udp-relay-gateway)** روی سرور دانلود داخل `download` خط زیر را اضافه کنید (IP و پورت رله را با واسط خودتان عوض کنید):

```json
"udp_relay": "TURKEY_PUBLIC_IP:9450"
```

در آن حالت روی همان سرور دیگر **`setcap cap_net_raw`** برای کانال دانلود لازم نیست؛ NAT را روی واسط با `scripts/linux_relay_udp_snat_turkey.sh` اعمال کنید.

#### پروکسی SOCKS بالادست برای اتصال TCP به مقصد (اختیاری — سمت سرور)

اگر سرور ترکیه برای رسیدن به `host:port` واقعی هر session (همان مقصدی که کلاینت در `Open` می‌فرستد) باید از یک SOCKS5 محلی عبور کند، در `server` فیلد `upstream_socks` را بگذارید (مثلاً `127.0.0.1:10809`). در این حالت **فقط** زنجیرهٔ dial سرور به مقصد TCP از آن SOCKS رد می‌شود؛ کانال UDP دانلود (spoof/relay) عوض نمی‌شود.

اگر خالی بگذارید یا مقدار `direct` / `none` بدهید، رفتار قبلی است: `Dial` مستقیم TCP به مقصد.

### ۳-۲) کانفیگ کلاینت (ایران) — `client.yaml`

```json
{
  "mode": "client",
  "psk": "dGVzdC1wYXNzd29yZC0zMi1ieXRlcy1rZXkhISE=",
  "log_level": "info",
  "client": {
    "listen": {
      "socks": "127.0.0.1:1080",
      "http": "127.0.0.1:1081"
    },
    "upstream_socks": "127.0.0.1:10808",
    "remote": "130.94.0.200:9443",
    "download": {
      "listen_udp": "0.0.0.0:9444",
      "spoof_source_ip": "194.225.101.22",
      "receive_timeout": "120s"
    },
    "protocol_version": 1
  }
}
```

> **نکتهٔ کلیدی**: مقدار `psk` در دو طرف باید دقیقاً یکسان باشد. همچنین `spoof_source_ip` در هر دو طرف باید یکی باشد و `iran_udp_port` در سرور = عدد پورت `listen_udp` در کلاینت.

فایل‌ها را در مسیر مناسب قرار دهید:

```bash
sudo mkdir -p /etc/ultraspoof
sudo cp server.yaml /etc/ultraspoof/server.yaml   # روی ترکیه
sudo cp client.yaml /etc/ultraspoof/client.yaml   # روی ایران
```

---

## گام ۴: اجرای سرویس‌ها

### روی ترکیه

```bash
/usr/local/bin/ultraSpoof -c /etc/ultraspoof/server.yaml
```

اگر از `setcap` استفاده نکرده‌اید، نیاز به `sudo` دارید:

```bash
sudo /usr/local/bin/ultraSpoof -c /etc/ultraspoof/server.yaml
```

### روی ایران

```bash
/usr/local/bin/ultraSpoof -c /etc/ultraspoof/client.yaml
```

با `log_level: info` پیام‌های «session ok / session failed» را می‌بینید. برای دیباگ از `log_level: debug` استفاده کنید.

---

## گام ۵: تست اتصال

### ۵-۱) چک کردن پروکسی محلی

روی سیستم کلاینت ایران:

```bash
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

باید IP ترکیه (یا IP سایت مقصد از دید ترکیه) را ببینید.

### ۵-۲) چک UDP ورودی روی ایران

اگر چیزی جواب نمی‌دهد، از tcpdump استفاده کنید:

```bash
sudo tcpdump -n -i any udp and port 9444
```

باید بسته‌های ورودی از `194.225.101.22` (همان `spoof_source_ip`) به IP ایران شما روی پورت `9444` دیده شوند. اگر چیزی دیده نمی‌شود، یعنی یا سرور ترکیه بسته‌ای نمی‌فرستد یا در مسیر drop می‌شود.

### ۵-۳) چک TCP کنترل

از ایران تست کنید که پورت کنترل ترکیه باز است:

```bash
nc -vz 130.94.0.200 9443
```

---

## توضیح کامل فیلدهای کانفیگ

### فیلدهای مشترک

| فیلد | معنی |
|------|------|
| `mode` | `"client"` (ایران) یا `"server"` (ترکیه). |
| `psk` | رمز مشترک. اگر base64 معتبر باشد، decode می‌شود؛ در غیر این صورت به‌صورت رشتهٔ خام استفاده می‌شود. حداقل ۱۶ بایت لازم است. |
| `log_level` | `""`/`off` (بدون لاگ اتصال)، `info` (خلاصه)، `debug` (کامل). |
| `protocol_version` | فعلاً `1`. اگر خالی بگذارید، پیش‌فرض `1` می‌شود. |

### فیلدهای `client`

| فیلد | معنی |
|------|------|
| `listen.socks` | آدرس و پورت SOCKS5 محلی. مثال: `127.0.0.1:1080`. |
| `listen.http` | آدرس و پورت HTTP CONNECT محلی (اختیاری). مثال: `127.0.0.1:1081`. |
| `upstream_socks` | SOCKS5 بالادست (Xray محلی در ایران). مثال: `127.0.0.1:10808`. |
| `remote` | آدرس `ultraSpoof` سرور ترکیه از نگاه شبکهٔ بیرون (بعد از عبور از Xray). مثال: `130.94.0.200:9443`. |
| `download.listen_udp` | پورت UDP که منتظر بسته‌های دانلود از ترکیه هست. مثال: `0.0.0.0:9444`. |
| `download.spoof_source_ip` | IP ای که سرور ترکیه به‌عنوان **منبع** بسته‌های UDP جعل می‌کند. کلاینت بسته‌هایی که از این IP نباشند را نادیده می‌گیرد. |
| `download.receive_timeout` | حداکثر زمان انتظار بین دو بسته UDP قبل از اعلام timeout. پیش‌فرض `120s`. |
| `download.socket_recv_buffer_bytes` | اندازهٔ `SO_RCVBUF` روی سوکت UDP (بایت). برای ترافیک سنگین مقادیر بزرگ (32-128 MB) لازم است تا burst‌ها drop نشوند. |
| `download.recv_sockets` | تعداد سوکت UDP موازی با `SO_REUSEPORT` (توزیع بار کرنل). پیش‌فرض `1`. برای چند کاربر همزمان `2-8` توصیه می‌شود. |
| `download.recv_workers` | تعداد goroutine موازی برای رمزگشایی AES-GCM بسته‌ها. پیش‌فرض = `min(NumCPU, 8)`. |
| `download.recv_batch_size` | حداکثر تعداد بستهٔ دریافتی در یک syscall `recvmmsg` (فقط Linux/amd64). پیش‌فرض `64`. |
| `download.session_queue_size` | ظرفیت صف هر session قبل از drop شدن بسته‌ها. پیش‌فرض `4096`. |

### فیلدهای `server`

| فیلد | معنی |
|------|------|
| `listen.tcp` | آدرس گوش‌دادن سرور برای کنترل. معمولاً `0.0.0.0:9443`. |
| `upstream_socks` | **اختیاری.** SOCKS5 محلی که اتصال TCP سرور به مقصد هر session از آن عبور می‌کند. خالی یا `direct` / `none` یعنی dial مستقیم به مقصد (پیش‌فرض). |
| `download.iran_ip` | IP عمومی سرور ایران شما (مقصد نهایی بسته‌های UDP برای کلاینت؛ در مسیر `udp_relay` روی واسط با DNAT اعمال می‌شود). |
| `download.iran_udp_port` | پورت UDP سرور ایران (برابر با پورت `listen_udp` در کلاینت). |
| `download.udp_relay` | اگر غیرخالی باشد (مثلاً `"203.0.113.1:9450"`)، ارسال دانلود با **UDP معمولی** به این آدرس انجام می‌شود و **raw spoof روی همین ماشین غیرفعال** است؛ روی واسط باید NAT مطابق `scripts/linux_relay_udp_snat_turkey.sh` تنظیم شود. خالی = همان رفتار قدیمی (spoof مستقیم از سرور). |
| `download.spoof_source_ip` | IP منبع جعلی روی بسته‌های UDP (بعد از SNAT روی واسط، کلاینت همین را می‌بیند). باید با `client.download.spoof_source_ip` یکسان باشد. |
| `download.spoof_udp_source_port` | پورت منبع UDP جعلی. `0` یعنی به‌صورت شبه‌تصادفی از بازهٔ ۳۵۰۰۰+. |
| `download.interface` | اینترفیس شبکه برای `SO_BINDTODEVICE` (مثلاً `eth0`). خالی یعنی انتخاب خودکار. |
| `download.max_chunk_size` | حداکثر اندازهٔ بستهٔ UDP (پیش‌فرض `1200` بایت، بازهٔ مجاز ۲۵۶ تا ۶۰۰۰۰). برای MTU 1500 می‌توانید تا `1400` بالا ببرید. |
| `download.target_read_buffer_bytes` | اندازهٔ بافر خواندن TCP از مقصد. پیش‌فرض `1048576` (۱MB). مقادیر بزرگ تعداد syscall را کم می‌کند. |
| `download.send_batch_size` | حداکثر تعداد بستهٔ UDP در یک syscall `sendmmsg`. پیش‌فرض `64`. |
| `download.send_workers` | تعداد raw socket fd موازی برای حذف قفل بین sessionها. پیش‌فرض `1`. برای لود بالا `NumCPU`. |
| `download.skip_udp_checksum` | `false` (پیش‌فرض): UDP checksum استاندارد محاسبه می‌شود (سازگار با همهٔ شبکه‌ها). `true`: checksum صفر فرستاده می‌شود → ~۱۵٪ CPU کمتر ولی بعضی middleboxها بسته را drop می‌کنند. |
| `download.socket_send_buffer_bytes` | اندازهٔ `SO_SNDBUF` روی هر raw fd. پیش‌فرض `16777216` (۱۶MB). |
| `download.pipeline_slots` | تعداد بافر در حلقهٔ double-buffer بین read/seal و sendmmsg. پیش‌فرض `4`. |

---

## تنظیمات پیشرفتهٔ عملکرد (Workers و بافرها)

**پیش‌فرض‌ها محافظه‌کارانه انتخاب شده‌اند** تا روی بیشترین کرنل‌ها/کانتینرها بدون دستکاری کار کنند. برای throughput جدی (ده‌ها یا صدها کاربر هم‌زمان) لازم است چند فیلد زیر را صریحاً بالا ببرید.

### مفهوم هر پارامتر

| پارامتر | جایی که استفاده می‌شود | نقش |
|---|---|---|
| `server.download.send_workers` | ترکیه | تعداد raw socket‌های موازی برای ارسال. هر session از یکی از آن‌ها با round-robin استفاده می‌کند. افزایش → contention کمتر. |
| `server.download.send_batch_size` | ترکیه | اندازهٔ batch در `sendmmsg` syscall. مقدار بزرگ‌تر = syscall کمتر = CPU کمتر روی هر Mbps. |
| `server.download.pipeline_slots` | ترکیه | double-buffering بین read (از target) و send (UDP spoofed). مقدار بزرگ‌تر اجازهٔ overlap بیشتر می‌دهد ولی حافظهٔ بیشتر مصرف می‌کند. |
| `server.download.target_read_buffer_bytes` | ترکیه | بافر `Read()` از target. مقدار بزرگ‌تر = chunking بهتر و syscall کمتر. |
| `server.download.socket_send_buffer_bytes` | ترکیه | `SO_SNDBUF` روی raw fd. جلوی drop شدن بسته‌ها هنگام burst را می‌گیرد. |
| `server.download.skip_udp_checksum` | ترکیه | صرفه‌جویی ۱۵-۲۰٪ CPU به‌قیمت خطر drop در middleboxهای سخت‌گیر. AEAD صحت داده را تضمین می‌کند، پس از منظر امنیت ایمن است. |
| `client.download.recv_sockets` | ایران | تعداد سوکت UDP موازی روی همان پورت (SO_REUSEPORT). کرنل بسته‌ها را بر اساس hash 4-tuple توزیع می‌کند → softirq روی چند CPU پخش می‌شود. |
| `client.download.recv_workers` | ایران | goroutineهای رمزگشایی AES-GCM. باید حداقل برابر تعداد coreها باشد. |
| `client.download.recv_batch_size` | ایران | اندازهٔ batch `recvmmsg`. مشابه سمت server ولی برای دریافت. |
| `client.download.socket_recv_buffer_bytes` | ایران | `SO_RCVBUF`. **مهم‌ترین** پارامتر برای جلوگیری از drop شدن UDP در حجم بالا. |
| `client.download.session_queue_size` | ایران | ظرفیت صف هر session. افزایش در حجم ترافیک بالا برای جلوگیری از drop لازم است. |

### قواعد کلی

1. **تعداد کاربر → تعداد worker**: تقریب اولیه `recv_workers ≈ send_workers ≈ NumCPU`.
2. **حجم ترافیک → اندازهٔ بافرها**: برای هر 100 Mbps، حداقل ۳۲ MB `socket_recv_buffer_bytes` توصیه می‌شود.
3. **تعداد session همزمان → session_queue_size و pipeline_slots**: اگر session queue پر می‌شود، از لاگ `udp session queue full` خواهید فهمید.
4. **MTU شبکه شما**: اگر مسیر MTU=1500 پایدار دارد، `max_chunk_size=1400` بگذارید (حدود ۱۶٪ header overhead کمتر).

---

## حالت Aggressive (بدون رمزنگاری، حداکثر سرعت)

برای سناریوهایی که **بیشترین سرعت و پایین‌ترین سربار CPU** ملاک است و محرمانگی داده در سطح پروتکل ضرورت ندارد (مثلاً وقتی خود داده قبلاً TLS است)، می‌توانید کانال UDP دانلود را روی حالت **plain** بگذارید.

### مقایسه

| ویژگی | `encryption: "aead"` (پیش‌فرض) | `encryption: "none"` (aggressive) |
|---|---|---|
| رمزنگاری UDP | AES-256-GCM روی هر بسته | ندارد |
| سربار هر بسته | 50 بایت (nonce + tag + header) | **23 بایت** فقط header |
| CPU سرور (ترکیه) | بالا (AES-GCM + محاسبهٔ checksum) | **پایین** |
| CPU کلاینت (ایران) | بالا (AES-GCM decrypt) | **پایین** |
| throughput typical | 1-3 Gbps (با tuning) | **تا ~2x بالاتر** از حالت AEAD |
| امنیت داده | محرمانه + ضد دستکاری | بدون محرمانگی |
| امنیت کنترل (TCP) | همچنان از داخل VLESS/TLS عبور می‌کند | همچنان از داخل VLESS/TLS عبور می‌کند |

### چه زمانی aggressive mode را انتخاب کنم؟

- **مناسب است وقتی**:
  - داده‌ای که از UDP عبور می‌کند **خودش رمزنگاری شده** (HTTPS, TLS, SSH) — که ۹۵٪ ترافیک وب امروز چنین است.
  - مسیر شبکه‌ای بین ترکیه و ایران به‌صورت direct peering است و شنود passive نگرانی‌تان نیست.
  - می‌خواهید **چند Gbps throughput** روی یک سرور متوسط بگیرید.

- **مناسب نیست وقتی**:
  - از UDP برای عبور ترافیک plain HTTP یا پروتکل‌های بدون encryption استفاده می‌کنید.
  - نگران MITM passive روی کل path هستید (AEAD جلوی شنود و تغییر داده را می‌گیرد).

### فعال‌سازی

فقط کافی است `encryption: "none"` را به بخش `download` **هر دو طرف** اضافه کنید:

**`server.yaml` (ترکیه):**
```json
{
  "mode": "server",
  "server": {
    "download": {
      "encryption": "none",
      ...
    }
  }
}
```

**`client.yaml` (ایران):**
```json
{
  "mode": "client",
  "client": {
    "download": {
      "encryption": "none",
      ...
    }
  }
}
```

> ⚠️ **مقدار باید در دو طرف دقیقاً یکسان باشد.** اگر سرور `"none"` بفرستد ولی کلاینت حالت `"aead"` باشد، همهٔ بسته‌ها با خطای `plain bad magic` drop می‌شوند (در debug log دیده می‌شود).

### نتیجهٔ عملی

- **سربار bandwidth**: ~3-4٪ (نسبت به headers IP/UDP) به جای ~6-8٪ در حالت AEAD — یعنی روی 1 Gbps خام، ~30-40 Mbps payload بیشتر.
- **CPU server**: AES-NI رو حذف می‌کند → می‌توانید با هر worker بیش از ۵۰۰ Mbps بزنید (در مقابل ~200 Mbps در حالت AEAD).
- **latency**: چند ده میکروثانیه کمتر در هر بسته (حذف Seal/Open).

### کانفیگ نمونهٔ اصلی aggressive

این نمونه برای **۲۰۰ کاربر همزمان با aggressive mode** است:

```json
{
  "mode": "server",
  "psk": "...",
  "log_level": "info",
  "server": {
    "listen": { "tcp": "0.0.0.0:9443" },
    "download": {
      "iran_ip": "...",
      "iran_udp_port": 9444,
      "spoof_source_ip": "...",
      "max_chunk_size": 1400,
      "encryption": "none",
      "target_read_buffer_bytes": 4194304,
      "send_batch_size": 128,
      "send_workers": 8,
      "skip_udp_checksum": true,
      "socket_send_buffer_bytes": 33554432,
      "pipeline_slots": 8
    }
  }
}
```

```json
{
  "mode": "client",
  "psk": "...",
  "client": {
    "listen": { "socks": "127.0.0.1:1080" },
    "upstream_socks": "127.0.0.1:10808",
    "remote": "TURKEY_IP:9443",
    "download": {
      "listen_udp": "0.0.0.0:9444",
      "spoof_source_ip": "...",
      "encryption": "none",
      "socket_recv_buffer_bytes": 67108864,
      "recv_workers": 8,
      "recv_sockets": 4,
      "recv_batch_size": 128,
      "session_queue_size": 16384
    }
  }
}
```

---

## پروفایل‌های آمادهٔ ترافیک (۱۰ / ۵۰ / ۲۰۰ / ۵۰۰ کاربر)

این اعداد تقریبی هستند و بر پایهٔ فرض «هر کاربر به‌صورت متوسط 2-5 Mbps هنگام تماشای ویدیو یا browsing فعال» محاسبه شده‌اند. اگر ترافیک شما سنگین‌تر است (دانلود انبوه همزمان)، از ستون بالاتر استفاده کنید.

### پروفایل A — ترافیک سبک (۱۰-۳۰ کاربر، ~ 50 Mbps مجموع)

**سرور ترکیه — حداقل ۲ CPU, 1 GB RAM:**
```json
{
  "download": {
    "max_chunk_size": 1400,
    "target_read_buffer_bytes": 524288,
    "send_batch_size": 32,
    "send_workers": 2,
    "skip_udp_checksum": false,
    "socket_send_buffer_bytes": 8388608,
    "pipeline_slots": 4
  }
}
```

**کلاینت ایران — حداقل ۲ CPU, 1 GB RAM:**
```json
{
  "download": {
    "socket_recv_buffer_bytes": 16777216,
    "recv_workers": 2,
    "recv_sockets": 1,
    "recv_batch_size": 32,
    "session_queue_size": 4096
  }
}
```

### پروفایل B — ترافیک متوسط (۵۰-۱۰۰ کاربر، ~ 200 Mbps مجموع)

**سرور ترکیه — حداقل ۴ CPU, 2 GB RAM:**
```json
{
  "download": {
    "max_chunk_size": 1400,
    "target_read_buffer_bytes": 1048576,
    "send_batch_size": 64,
    "send_workers": 4,
    "skip_udp_checksum": false,
    "socket_send_buffer_bytes": 16777216,
    "pipeline_slots": 6
  }
}
```

**کلاینت ایران — حداقل ۴ CPU, 2 GB RAM:**
```json
{
  "download": {
    "socket_recv_buffer_bytes": 33554432,
    "recv_workers": 4,
    "recv_sockets": 2,
    "recv_batch_size": 64,
    "session_queue_size": 8192
  }
}
```

### پروفایل C — ترافیک سنگین (۲۰۰ کاربر، ~ 500-800 Mbps مجموع) ⭐

**این پروفایل برای سؤال شما («سرور با ۲۰۰ کاربر») است.**

**سرور ترکیه — توصیه: ۸ CPU, 4 GB RAM, NIC gigabit با `tx-queue` بزرگ:**
```json
{
  "mode": "server",
  "psk": "...",
  "log_level": "info",
  "server": {
    "listen": { "tcp": "0.0.0.0:9443" },
    "download": {
      "iran_ip": "92.242.220.190",
      "iran_udp_port": 9444,
      "spoof_source_ip": "194.225.101.22",
      "spoof_udp_source_port": 0,
      "interface": "eth0",
      "max_chunk_size": 1400,
      "target_read_buffer_bytes": 2097152,
      "send_batch_size": 128,
      "send_workers": 8,
      "skip_udp_checksum": true,
      "socket_send_buffer_bytes": 33554432,
      "pipeline_slots": 8
    },
    "protocol_version": 1
  }
}
```

**کلاینت ایران — توصیه: ۸ CPU, 4 GB RAM, NIC gigabit:**
```json
{
  "mode": "client",
  "psk": "...",
  "log_level": "info",
  "client": {
    "listen": { "socks": "127.0.0.1:1080" },
    "upstream_socks": "127.0.0.1:10808",
    "remote": "TURKEY_PUBLIC_IP:9443",
    "download": {
      "listen_udp": "0.0.0.0:9444",
      "spoof_source_ip": "194.225.101.22",
      "receive_timeout": "120s",
      "socket_recv_buffer_bytes": 67108864,
      "recv_workers": 8,
      "recv_sockets": 4,
      "recv_batch_size": 128,
      "session_queue_size": 16384
    },
    "protocol_version": 1
  }
}
```

> **نکتهٔ مهم**: در این پروفایل `skip_udp_checksum: true` گذاشته‌ایم. اگر مسیر بین ترکیه-ایران شما بسته‌های UDP checksum=0 را قبول می‌کند، این گزینه ۱۵-۲۰٪ CPU آزاد می‌کند. اگر شک دارید، اول با `false` تست کنید.

### پروفایل D — ترافیک خیلی سنگین (۵۰۰+ کاربر، > 1 Gbps)

**سرور ترکیه — توصیه: ۱۶ CPU, 8 GB RAM, NIC 10G:**
```json
{
  "download": {
    "max_chunk_size": 1400,
    "target_read_buffer_bytes": 4194304,
    "send_batch_size": 256,
    "send_workers": 16,
    "skip_udp_checksum": true,
    "socket_send_buffer_bytes": 67108864,
    "pipeline_slots": 12
  }
}
```

**کلاینت ایران — توصیه: ۱۶ CPU, 8 GB RAM, NIC 10G:**
```json
{
  "download": {
    "socket_recv_buffer_bytes": 134217728,
    "recv_workers": 16,
    "recv_sockets": 8,
    "recv_batch_size": 256,
    "session_queue_size": 32768
  }
}
```

> در این حجم، بدون tuning سطح کرنل (بخش بعدی) این پروفایل به خروجی نمی‌رسد.

### راهنمای سایزبندی سریع

| تعداد کاربر | CPU پیشنهادی | RAM | `recv_workers` / `send_workers` | `recv_sockets` | `SO_RCVBUF` | `SO_SNDBUF` |
|---|---|---|---|---|---|---|
| ≤ 30 | 2 | 1 GB | 2 | 1 | 16 MB | 8 MB |
| 50-100 | 4 | 2 GB | 4 | 2 | 32 MB | 16 MB |
| **200** | **8** | **4 GB** | **8** | **4** | **64 MB** | **32 MB** |
| 500+ | 16 | 8 GB | 16 | 8 | 128 MB | 64 MB |

---

## Tuning سطح کرنل (sysctl / ulimit / NIC)

**این بخش بسیار مهم است**: بدون این تنظیمات، بافرهای بزرگی که در کانفیگ گذاشته‌اید توسط کرنل کوچک می‌شوند و throughput شما همان چند ده Mbps باقی می‌ماند.

### ۱) sysctl — هر دو سرور

فایل `/etc/sysctl.d/99-ultraspoof.conf` را بسازید:

```conf
# افزایش سقف بافرهای سوکت (از 4MB پیش‌فرض به 256MB)
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432

# صف پکت ورودی NIC قبل از پردازش softirq
net.core.netdev_max_backlog = 300000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# تعداد اتصال در صف accept (برای TCP کنترل)
net.core.somaxconn = 65535

# memory pool برای UDP (min / pressure / max، واحد page یعنی 4KB)
net.ipv4.udp_mem = 379008 505344 758016

# بافرهای TCP (برای تونل کنترل و target)
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# TCP congestion control مدرن (BBR بهتر از cubic برای لینک با latency بالا)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open (هر دو طرف)
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_no_metrics_save = 1

# فقط سمت ایران: خاموش کردن rp_filter (برای قبول بسته‌های UDP با source spoofed)
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# افزایش ظرفیت conntrack (اگر nf_conntrack load شده)
net.netfilter.nf_conntrack_max = 1048576
```

اعمال:
```bash
sudo sysctl --system
# یا:
sudo sysctl -p /etc/sysctl.d/99-ultraspoof.conf
```

### ۲) ulimit — تعداد file descriptor

برای سرویس systemd، در فایل `.service` اضافه کنید:
```ini
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
```

یا سراسری در `/etc/security/limits.conf`:
```conf
* soft nofile 1048576
* hard nofile 1048576
```

### ۳) NIC queues (`ethtool`) — هر دو طرف

کارت شبکه معمولاً چند rx/tx queue دارد که با هر irq به یک CPU pin می‌شود:

```bash
# تعداد queue فعلی را ببینید
ethtool -l eth0

# به حداکثر مقدار تنظیم کنید (مثلاً 8):
sudo ethtool -L eth0 combined 8

# اندازهٔ ring buffer کارت شبکه را حداکثر کنید
ethtool -g eth0
sudo ethtool -G eth0 rx 4096 tx 4096

# pacing offload (اگر پشتیبانی شود)
sudo ethtool -K eth0 tso on gso on gro on
```

برای توزیع IRQ روی CPUها:
```bash
sudo systemctl disable --now irqbalance
# سپس نسبت به تعداد queue دستی تنظیم: مثلاً eth0-rx-0 → CPU0, rx-1 → CPU1 ...
# یا با ابزار: https://github.com/syncookie/set_irq_affinity
```

### ۴) CAP_NET_RAW (فقط ترکیه)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/ultraSpoof
```

`cap_net_admin` اجازه می‌دهد ultraSpoof از `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` برای دور زدن سقف `rmem_max` استفاده کند.

### ۵) GOMAXPROCS و CPU pinning (اختیاری)

اگر سرور dedicated است، به طور پیش‌فرض Go از همهٔ coreها استفاده می‌کند. اگر container است با cgroup محدود، حتماً:
```bash
export GOMAXPROCS=$(nproc)
```

برای pin کردن به NUMA node خاص روی سرورهای چندسوکته:
```bash
numactl --cpunodebind=0 --membind=0 /usr/local/bin/ultraSpoof -c ...
```

### چک‌لیست نهایی سطح کرنل

- [ ] `sysctl --system` اعمال شده؟
- [ ] `ulimit -n` بیش از ۱M هست؟
- [ ] `rp_filter=0` روی سرور ایران؟
- [ ] `setcap cap_net_raw,cap_net_admin` روی باینری ترکیه؟
- [ ] `tcp_congestion_control = bbr` فعال؟ (چک: `sysctl net.ipv4.tcp_congestion_control`)
- [ ] تعداد queue NIC و IRQ affinity تنظیم شده؟

---

## اجرا به‌صورت systemd

### سرور ترکیه: `/etc/systemd/system/ultraspoof-server.service`

```ini
[Unit]
Description=ultraSpoof server (Turkey)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ultraSpoof -c /etc/ultraspoof/server.yaml
Restart=on-failure
RestartSec=2

# مجوز ارسال raw packet و تنظیم بافر بالاتر از سقف
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# سقف file descriptor و process برای ترافیک سنگین
LimitNOFILE=1048576
LimitNPROC=1048576

# استفادهٔ کامل از CPU
CPUAccounting=true
Nice=-5

[Install]
WantedBy=multi-user.target
```

### کلاینت ایران: `/etc/systemd/system/ultraspoof-client.service`

```ini
[Unit]
Description=ultraSpoof client (Iran)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ultraSpoof -c /etc/ultraspoof/client.yaml
Restart=on-failure
RestartSec=2

# برای SO_RCVBUFFORCE (گذر از net.core.rmem_max)
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

LimitNOFILE=1048576
LimitNPROC=1048576

CPUAccounting=true
Nice=-5

[Install]
WantedBy=multi-user.target
```

فعال‌سازی:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ultraspoof-server      # ترکیه
sudo systemctl enable --now ultraspoof-client      # ایران
sudo journalctl -u ultraspoof-server -f            # مشاهدهٔ لاگ
```

---

## لاگ‌گیری و عیب‌یابی

سه سطح لاگ وجود دارد:

- `off` / خالی → هیچ پیامی دربارهٔ اتصال‌ها چاپ نمی‌شود (فقط خطاهای بحرانی).
- `info` → برای هر نشست یک خط «ok» یا «failed».
- `debug` → شامل جزییات دقیق هر مرحله (handshake، baz شدن نشست، دریافت UDP، ...).

مثال خروجی `info` در سمت کلاینت:

```
[INFO] session ok peer=127.0.0.1:54932 target=www.google.com:443
[INFO] session failed peer=127.0.0.1:54934 target=example.invalid:443 err=remote error: dial tcp ...
```

---

## رفع اشکال (Troubleshooting)

### ۱) خطا: `config: ... psk must decode to at least 16 bytes`

مقدار `psk` شما خیلی کوتاه است. یک کلید جدید بسازید:

```bash
openssl rand -base64 32
```

### ۲) خطا: `config: client.remote: ...`

آدرس `remote` را به‌صورت `host:port` بنویسید و مطمئن شوید پورت عدد صحیح بین ۱ تا ۶۵۵۳۵ است.

### ۳) `curl` از پروکسی پاسخ نمی‌دهد

- آیا Xray محلی ایران روی `127.0.0.1:10808` فعال است؟ با `nc -vz 127.0.0.1 10808` چک کنید.
- آیا پورت `9443/tcp` ترکیه از ایران قابل اتصال است؟ با `nc -vz TURKEY_IP 9443` چک کنید.
- لاگ کلاینت را با `log_level: debug` روشن کنید.

### ۴) `session ok` می‌گیریم ولی هیچ دیتایی به مرورگر نمی‌رسد (timeout)

این یعنی مسیر آپلود کار می‌کند ولی UDP دانلود نمی‌رسد:

- روی ایران: `sudo tcpdump -n -i any udp and port 9444` — آیا بسته‌ای از `spoof_source_ip` دیده می‌شود؟
- اگر دیده نمی‌شود: بررسی کنید سرور ترکیه مجوز raw socket دارد (`setcap`) و `interface` درست انتخاب شده.
- اگر دیده می‌شود ولی به اپ نمی‌رسد: `rp_filter` را چک کنید، یا مطمئن شوید ultraSpoof کلاینت UDP را روی همان پورت bind کرده (نه روی اینترفیس دیگر).

### ۵) خطا: `spoof UDP send is only implemented on linux`

سرور را روی لینوکس اجرا کنید. ویندوز برای سمت سرور پشتیبانی نمی‌شود.

### ۶) خطا: `raw socket: operation not permitted`

به باینری ترکیه `CAP_NET_RAW` بدهید یا با root اجرا کنید:

```bash
sudo setcap cap_net_raw+eip /usr/local/bin/ultraSpoof
```

### ۷) `timeout waiting for first download UDP packet`

اولین بستهٔ UDP دانلود در ۱۰ دقیقهٔ اول نرسید. علت معمولاً drop شدن در مسیر شبکه (فیلترینگ ISP ایران روی منابع جعلی، یا فایروال سرور ایران) است. با `tcpdump` ورودی بودن را بررسی کنید.

### ۸) سرعت پایین با وجود اتصال موفق

اگر `curl` جواب می‌گیرد ولی throughput پایین است:

۱. **لاگ دیباگ چک کنید**: `log_level: debug` بگذارید و ببینید این پیام‌ها ظاهر می‌شوند:
   - `udp hub queue full, dropping packet` → `session_queue_size` یا `recv_workers` را زیاد کنید
   - `udp session queue full, dropping seq=N` → `session_queue_size` را زیاد کنید
   - `udp drop: decrypt/parse failed` → بستهٔ خراب (MTU یا PSK ناسازگار)
   - `udp drop: filter mismatch` → `spoof_source_ip` در دو طرف هماهنگ نیست

۲. **`ss -u -n -m`** روی ایران: ستون `rcv-q` اگر دائماً نزدیک `socket_recv_buffer_bytes` است، بافر کم است.

۳. **بافرها واقعاً بزرگ شدند؟**
   ```bash
   cat /proc/net/udp  # ستون rx_queue اگر بزرگ است یعنی drop دارید
   ss -u -n -m
   ```
   اگر `sysctl net.core.rmem_max` هنوز `212992` است، فایل `sysctl` اعمال نشده.

۴. **CPU اشباع شده؟**
   ```bash
   top -H -p $(pgrep ultraSpoof)
   ```
   اگر یک thread صد درصد است، `recv_workers` یا `send_workers` را زیاد کنید و `recv_sockets` را.

۵. **از پروفایل C یا D (بخش پیشنهادات ۲۰۰ کاربر) استفاده کنید** و sysctlها را اعمال کنید.

### ۹) `udp drop: filter mismatch src=0.0.0.0`

این خطا پیش از فیکس dual-stack دیده می‌شد. اگر هنوز می‌بینید، یعنی باینری قدیمی استفاده می‌کنید. جدید را دوباره بیلد و deploy کنید.

### ۱۰) بسته‌ها روی ترکیه ارسال می‌شوند ولی روی ایران `tcpdump` چیزی نشان نمی‌دهد

احتمال بالا: ISP ترکیه یا مسیر بین‌الملل `uRPF strict` دارد و بسته‌های با source IP بیرونی را drop می‌کند. برای تست موقت `spoof_source_ip` را روی IP واقعی سرور ترکیه بگذارید و ببینید آیا می‌رسد؛ اگر بله، مسیر uRPF دارد و این ابزار در آن مسیر کار نمی‌کند.

### ۱۱) تعداد زیادی `session failed ... err=udp download idle timeout`

چند session OK می‌شوند و بعضی‌ها پس از ۱۲۰ ثانیه با این خطا می‌میرند. دلایل رایج:

- **اپ کاربر خیلی سریع disconnect می‌کند**: بعضی اپ‌ها (Telegram, Google XMPP, mtalk) اگر پاسخ اولیه را در چند ثانیه نگیرند، اتصال را می‌بندند. از نسخهٔ فعلی به بعد وقتی اپ اتصال SOCKS را می‌بندد، session بلافاصله خاتمه می‌یابد (قبلاً ۱۲۰s معطل می‌شد).
- **target پاسخ نمی‌دهد**: برخی سرویس‌ها تا وقتی کلاینت اولین data (client hello) را نفرستد پاسخی نمی‌دهند. اگر اپ کاربر client hello را ارسال نکند، سرور ترکیه هم چیزی به ایران نمی‌فرستد → idle. چک کنید `xray log` روی ایران خطا نمی‌دهد.
- **rate limit مسیر**: روی flood مثلاً در اوج ترافیک، ISP ترکیه بستهٔ spoof را drop می‌کند. چک با `tcpdump` روی ایران و مقایسهٔ تعداد بسته.
- **حالت aggressive/plain در دو طرف ناهماهنگ است**: اگر سرور `encryption: "none"` ولی کلاینت AEAD (یا برعکس) باشد، همه بسته‌ها drop می‌شوند. در debug log پیام `plain bad magic` یا `decrypt/parse failed` می‌بینید.

---

## جزییات فنی پروتکل

این بخش برای کنجکاوهاست؛ برای راه‌اندازی لازم نیست.

### کانال کنترل (TCP بین کلاینت و سرور)

هر فریم:

```
magic(4) = "USp\x01"  |  cmd(1)  |  body_len(4, big-endian)  |  body
```

دستورات:

| کد | نام | جهت |
|----|-----|------|
| `0x01` | `CmdOpen`   | client → server (باز کردن نشست و اتصال به `host:port`) |
| `0x02` | `CmdData`   | client → server (دیتای آپلود) |
| `0x03` | `CmdClose`  | client → server (پایان) |
| `0x80` | `CmdOpenOK` | server → client (تأیید باز شدن) |
| `0x81` | `CmdError`  | server → client (پیام خطا) |

هر نشست یک `session_id` ۱۶ بایتی دارد.

### کانال دانلود (UDP یک‌طرفه ترکیه → ایران با IP منبع جعلی)

ساختار هر بسته UDP:

```
nonce(12)  ||  AES-256-GCM_Seal( key, nonce, plaintext )
```

که `plaintext`:

```
version(1)=1 | session_id(16) | seq(4) | flags(1) | chunk(...)
flags: 0 = Data, 1 = FIN
```

کلید AEAD: `HMAC-SHA256("ultraSpoof-udp-v1", PSK)` (۳۲ بایت).

نانس: `sid[0:4] || seq(BE) || sid[4:8]` (۱۲ بایت).

### Reassembly سمت کلاینت

شماره‌های `seq` از `0` شروع می‌شوند. کلاینت هر `seq` کوچک‌تر از `next` را drop می‌کند و بزرگ‌ترها را در pending نگه می‌دارد تا نوبتشان برسد. بستهٔ با `flags=FIN` پایان استریم است.

---

## ملاحظات امنیتی و قانونی

- **PSK** را محرمانه نگه دارید. لو رفتن آن یعنی کسی می‌تواند ترافیک UDP شما را جعل یا رمزگشایی کند.
- ارسال بسته با **IP منبع جعلی** ممکن است بسته به ISP و قوانین محلی محدودیت داشته باشد. پیش از استفاده در production، سیاست شبکهٔ هاستینگ ترکیه را چک کنید.
- این ابزار برای دور زدن سیستم‌های امنیتی سخت‌گیر (مثل ضدجعل منبع در لبهٔ بعضی شبکه‌ها) طراحی نشده و در آن شبکه‌ها کار نمی‌کند؛ اگر مسیر بین‌المللی شما از uRPF سخت عبور می‌کند، بسته‌های spoof حذف می‌شوند.
- همیشه ارتباط کنترل (TCP) را از داخل یک تونل رمزنگاری‌شده (Xray/VLESS روی TLS) عبور دهید تا هم محرمانه باشد و هم مقاوم در برابر شناسایی.

---

## مرجع سریع دستورات

```bash
openssl rand -base64 32                                        ساخت PSK جدید
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/ultraSpoof   مجوز raw socket + تنظیم بافر (در مسیر udp_relay روی سرور دانلود لازم نیست)
sudo sysctl -p /etc/sysctl.d/99-ultraspoof.conf                 اعمال sysctl ها
sudo -E ./scripts/linux_relay_tcp_dnat.sh apply                  رلهٔ TCP کنترل روی واسط (متغیرهای env در ابتدای اسکریپت)
sudo -E ./scripts/linux_relay_udp_snat_turkey.sh apply           رلهٔ UDP + SNAT spoof روی واسط
/usr/local/bin/ultraSpoof -c /etc/ultraspoof/server.yaml        اجرای سرور ترکیه
/usr/local/bin/ultraSpoof -c /etc/ultraspoof/client.yaml        اجرای کلاینت ایران
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org          تست از طریق پروکسی
curl -x socks5h://127.0.0.1:1080 -o /dev/null \
     https://speed.cloudflare.com/__down?bytes=104857600        تست throughput 100MB
sudo tcpdump -n -i any udp and port 9444                        بررسی UDP ورودی
sudo journalctl -u ultraspoof-client -f                         لاگ سرویس
ss -u -n -m | grep 9444                                         بررسی وضعیت بافر UDP
top -H -p $(pgrep ultraSpoof)                                   بررسی CPU هر thread
```

اگر همهٔ مراحل را درست رفته باشید، درخواست `curl` بالا باید IP سرور ترکیه (یا هر IP ای که سایت مقصد می‌بیند) را برگرداند و همه چیز آماده است.
