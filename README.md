# MasterHttpRelayVPN-RUST

Rust port of [@masterking32's MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN). **All credit for the original idea and the Python implementation goes to [@masterking32](https://github.com/masterking32).** This is a faithful Rust reimplementation of the `apps_script` mode packaged as a single static binary.

Free DPI bypass via Google Apps Script as a remote relay and TLS SNI concealment. Your ISP's censor sees traffic going to `www.google.com`; behind the scenes a free Google Apps Script fetches the real website for you.

**[English Guide](#setup-guide)** | **[Persian Guide](#%D8%B1%D8%A7%D9%87%D9%86%D9%85%D8%A7%DB%8C-%D9%81%D8%A7%D8%B1%D8%B3%DB%8C)**

## Why this exists

The original Python project is excellent but requires Python + `pip install cryptography + h2` + runtime deps. For users in hostile networks, that install process is often itself broken (blocked PyPI, missing wheels, Windows without Python). This port is a single ~2.5 MB executable that you download and run. Nothing else.

## How it works

```
Browser -> mhrv-rs (local HTTP proxy) -> TLS to Google IP with SNI=www.google.com
                                                |
                                                | Host: script.google.com (inside TLS)
                                                v
                                         Apps Script relay (your free Google account)
                                                |
                                                v
                                         Real destination
```

The censor's DPI sees `www.google.com` in the TLS SNI and lets it through. Google's frontend hosts both `www.google.com` and `script.google.com` on the same IP and routes by the HTTP Host header inside the encrypted stream.

## Platforms

Linux (x86_64/aarch64), macOS (x86_64/aarch64), Windows (x86_64). Prebuilt binaries on the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases).

## Setup Guide

### Step 1: Deploy the Apps Script relay (one-time)

This part is unchanged from the original project. Follow @masterking32's guide, or the summary below:

1. Open <https://script.google.com> with your Google account
2. **New project**, delete the default code
3. Copy the contents of [`Code.gs` from the original repo](https://github.com/masterking32/MasterHttpRelayVPN/blob/main/Code.gs) into the editor
4. **Change** the line `const AUTH_KEY = "..."` to a strong secret only you know
5. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
6. Copy the **Deployment ID** (long random string in the URL).

### Step 2: Download mhrv-rs

Download the right binary from the [releases page](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) for your platform. Or build from source:

```bash
cargo build --release
```

### Step 3: Configure

Copy `config.example.json` to `config.json` and fill in your values:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "same-secret-as-in-code-gs",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true
}
```

`script_id` can also be an array of IDs for round-robin rotation across multiple deployments (higher quota, more throughput).

### Step 4: Install the MITM CA (one-time)

The tool needs to decrypt your browser's HTTPS locally so it can forward each request through the Apps Script relay. First run generates a local CA; install it as trusted:

```bash
# Linux / macOS
sudo ./mhrv-rs --install-cert

# Windows (Administrator)
mhrv-rs.exe --install-cert
```

The CA is saved at `./ca/ca.crt` — only you have the private key.

### Step 5: Run

```bash
./mhrv-rs --config config.json      # Linux/macOS
mhrv-rs.exe --config config.json    # Windows
```

### Step 6: Point your browser at the proxy

Configure your browser to use HTTP proxy `127.0.0.1:8085`.

- **Firefox**: Settings → Network Settings → Manual proxy → enter for HTTP, check "Also use this proxy for HTTPS"
- **Chrome/Edge**: System proxy settings, or use SwitchyOmega extension
- **macOS system-wide**: System Settings → Network → Wi-Fi → Details → Proxies → Web + Secure Web Proxy

## What's implemented vs not

This port focuses on the **`apps_script` mode** which is the only one that reliably works in 2025. Implemented:

- [x] Local HTTP proxy (CONNECT for HTTPS, plain forwarding for HTTP)
- [x] MITM with on-the-fly per-domain cert generation
- [x] CA generation + auto-install on macOS/Linux/Windows
- [x] Apps Script JSON relay (single-request mode), protocol-compatible with `Code.gs`
- [x] Connection pooling (45s TTL, max 20 idle)
- [x] Multi-script round-robin
- [x] Automatic redirect handling on the relay
- [x] Header filtering (strip connection-specific + brotli)

Deferred (PRs welcome):

- [ ] HTTP/2 multiplexing
- [ ] Request batching (`q: [...]` mode in `Code.gs`)
- [ ] Request coalescing for concurrent identical GETs
- [ ] Response cache
- [ ] Range-based parallel download for large files
- [ ] SNI-rewrite tunnels for YouTube/googlevideo (currently routes through full MITM+relay)
- [ ] Firefox NSS cert install (manual: import `ca/ca.crt` in Firefox preferences)
- [ ] Other modes (`domain_fronting`, `google_fronting`, `custom_domain`) — mostly broken post-Cloudflare 2024 crackdown, not a priority

## License

MIT. See [LICENSE](LICENSE).

## Credit

Original project: <https://github.com/masterking32/MasterHttpRelayVPN> by [@masterking32](https://github.com/masterking32). The idea, the Google Apps Script protocol, the proxy architecture, and the ongoing maintenance are all his. This Rust port exists only to make the client-side distribution easier.

---

## راهنمای فارسی

پورت Rust پروژه [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN) از [@masterking32](https://github.com/masterking32). **تمام اعتبار ایده و نسخه اصلی Python متعلق به ایشان است.** این نسخه فقط مدل `apps_script` را به‌صورت یک فایل اجرایی مستقل (بدون نیاز به نصب Python) ارائه می‌دهد.

### چرا این نسخه؟

نسخه اصلی Python عالی است ولی نیاز به Python + نصب `cryptography` و `h2` دارد. برای کاربرانی که PyPI فیلتر شده یا Python ندارند، این فرایند خودش مشکل است. این پورت فقط یک فایل ~۲.۵ مگابایتی است که دانلود می‌کنید و اجرا می‌کنید.

### نحوه کار

مرورگر شما با این ابزار به‌عنوان HTTP proxy صحبت می‌کند. ابزار ترافیک را از طریق TLS به IP گوگل می‌فرستد ولی SNI را `www.google.com` می‌گذارد. داخل TLS رمزگذاری‌شده، HTTP request به `script.google.com` می‌رود. DPI فقط `www.google.com` را می‌بیند. Apps Script سایت مقصد را واکشی و پاسخ را برمی‌گرداند.

### مراحل راه‌اندازی

#### ۱. راه‌اندازی Apps Script (یک‌بار)

این بخش دقیقاً همان نسخه اصلی است:

1. به <https://script.google.com> بروید و با اکانت گوگل وارد شوید
2. **New project** بزنید، کد پیش‌فرض را پاک کنید
3. محتوای [`Code.gs`](https://github.com/masterking32/MasterHttpRelayVPN/blob/main/Code.gs) را از ریپو اصلی کپی کنید و Paste کنید
4. در خط `const AUTH_KEY = "..."` رمز را به یک مقدار قوی و مخصوص خودتان تغییر دهید
5. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
6. **Deployment ID** (رشته تصادفی طولانی) را کپی کنید

#### ۲. دانلود mhrv-rs

از [صفحه releases](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases) باینری پلتفرم خود را دانلود کنید.

#### ۳. تنظیمات

فایل `config.example.json` را به `config.json` کپی کنید و مقادیر را پر کنید. `script_id` می‌تواند یک رشته یا آرایه‌ای از رشته‌ها باشد (برای چرخش بین چند deployment).

#### ۴. نصب CA (یک‌بار)

ابزار باید TLS مرورگر شما را محلی رمزگشایی کند. بار اول یک CA می‌سازد که باید trust کنید:

```bash
# لینوکس/مک
sudo ./mhrv-rs --install-cert

# ویندوز (Administrator)
mhrv-rs.exe --install-cert
```

#### ۵. اجرا

```bash
./mhrv-rs --config config.json
```

#### ۶. تنظیم proxy در مرورگر

Proxy مرورگر را روی `127.0.0.1:8085` بگذارید (هم HTTP و هم HTTPS).

### اعتبار

پروژه اصلی: <https://github.com/masterking32/MasterHttpRelayVPN> توسط [@masterking32](https://github.com/masterking32). تمام ایده، پروتکل Apps Script، و نگهداری متعلق به ایشان است. این پورت Rust فقط برای ساده کردن توزیع سمت کلاینت است.
