import hashlib
import json
import re
import socket
import ssl
import urllib.parse
import urllib.request
from datetime import datetime

import requests

# ============================================================
# КИБЕР-ЗАЩИТА И БЕЛЫЙ ХАКЕР — LEGAL API
# Все функции используют только публичные/открытые сервисы.
# ============================================================

UA = {"User-Agent": "Mozilla/5.0 (JusticeBot/WhiteHat)"}


# ================= 1. АНАЛИЗ URL НА ФИШИНГ =================

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz", ".top",
                   ".club", ".work", ".icu", ".vip", ".fun", ".site", ".online"}

PHISHING_KEYWORDS = ["login", "verify", "account", "update", "secure",
                     "banking", "confirm", "signin", "wallet", "free", "win", "prize"]


def analyze_url(url: str) -> dict:
    """Полный анализ URL на фишинг/мошенничество."""
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    score = 0
    flags = []

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        score += 30
        flags.append(f"⚠️ Подозрительный TLD ({tld})")

    if len(domain) > 50:
        score += 15
        flags.append("⚠️ Очень длинный домен")

    if domain.count("-") > 3:
        score += 20
        flags.append("⚠️ Много дефисов в домене")

    ip_match = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)
    if ip_match:
        score += 40
        flags.append("🚨 Домен = IP-адрес (подмена)")

    if "@" in url or "//" in url[8:]:
        score += 15
        flags.append("⚠️ Спецсимволы в URL")

    ascii_domain = domain.encode("ascii", "ignore").decode()
    if ascii_domain != domain:
        score += 25
        flags.append("⚠️ IDN-домен (подмена кириллицей)")

    path_parts = path.split("/")
    for kw in PHISHING_KEYWORDS:
        if kw in domain or kw in path:
            score += 10
            flags.append(f"⚠️ Фишинг-слово: {kw}")

    if url.count("//") > 2 or url.count("@") > 1:
        score += 20
        flags.append("⚠️ Скрытый редирект")

    shortened = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
    if any(s in domain for s in shortened):
        score += 5
        flags.append("ℹ️ Сокращённая ссылка")

    level = "ЧИСТО" if score < 10 else "НИЗКИЙ" if score < 25 else "СРЕДНИЙ" if score < 50 else "ВЫСОКИЙ"

    return {
        "url": url,
        "domain": domain,
        "tld": tld,
        "level": level,
        "score": min(score, 100),
        "flags": flags,
    }


# ================= 2. ПРОВЕРКА БЕЗОПАСНОСТИ САЙТА =================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"desc": "HSTS (принудительный HTTPS)", "weight": 20},
    "Content-Security-Policy": {"desc": "CSP (защита от XSS)", "weight": 18},
    "X-Frame-Options": {"desc": "X-Frame-Options (защита от clickjacking)", "weight": 15},
    "X-Content-Type-Options": {"desc": "X-Content-Type-Options (MIME sniffing)", "weight": 10},
    "X-XSS-Protection": {"desc": "X-XSS-Protection (старый XSS)", "weight": 8},
    "Referrer-Policy": {"desc": "Referrer-Policy (утечка реферера)", "weight": 8},
    "Permissions-Policy": {"desc": "Permissions-Policy (контроль фич)", "weight": 10},
}


def check_site_security(url: str) -> dict:
    """Проверка HTTP-заголовков безопасности сайта."""
    try:
        r = requests.get(url, timeout=10, headers=UA, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        found = []
        missing = []
        total = sum(h["weight"] for h in SECURITY_HEADERS.values())
        got = 0

        for hdr, info in SECURITY_HEADERS.items():
            if hdr.lower() in headers:
                found.append(f"✅ {info['desc']} = {headers[hdr.lower()][:60]}")
                got += info["weight"]
            else:
                missing.append(f"❌ Нет: {info['desc']}")

        score = round(got / total * 100) if total else 0
        ssl_ok = url.startswith("https://")
        server = r.headers.get("Server", "?")
        powered = r.headers.get("X-Powered-By", "?")

        return {
            "url": r.url,
            "status": r.status_code,
            "ssl": ssl_ok,
            "server": server,
            "powered_by": powered,
            "score": score,
            "found": found,
            "missing": missing,
            "security_grade": "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F",
        }
    except Exception as e:
        return {"error": str(e), "url": url}


# ================= 3. SSL/TLS СЕРТИФИКАТ =================

def check_ssl(hostname: str, port: int = 443) -> dict:
    """Проверка SSL/TLS сертификата."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(8)
            s.connect((hostname, port))
            cert = s.getpeercert()

        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        sans = [e[1] for e in cert.get("subjectAltName", [])]

        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        return {
            "host": hostname,
            "valid": True,
            "issuer": issuer.get("organizationName", "?"),
            "subject": subject.get("commonName", "?"),
            "not_before": not_before,
            "not_after": not_after,
            "days_left": days_left,
            "san_count": len(sans),
            "warning": "⚠️ Истекает через 30 дней!" if days_left < 30 else None,
            "danger": "🚨 ИСТЁК!" if days_left < 0 else None,
            "protocol": s.version(),
        }
    except ssl.SSLCertVerificationError as e:
        return {"host": hostname, "valid": False, "error": str(e)}
    except Exception as e:
        return {"host": hostname, "valid": False, "error": str(e)}


# ================= 4. DNS БЕЗОПАСНОСТИ (DMARC, SPF, DKIM) =================

def check_email_security(domain: str) -> dict:
    """Проверка DMARC, SPF, DKIM — защищён ли email-домен от подделки."""
    results = {}

    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT",
                         headers=UA, timeout=8)
        answers = r.json().get("Answer", [])
        spf = [a["data"] for a in answers if "spf" in a.get("data", "").lower()]
        results["spf"] = spf[0] if spf else None
    except Exception:
        results["spf"] = None

    try:
        r = requests.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
                         headers=UA, timeout=8)
        answers = r.json().get("Answer", [])
        dmarc = [a["data"] for a in answers if "dmarc" in a.get("data", "").lower()]
        results["dmarc"] = dmarc[0] if dmarc else None
    except Exception:
        results["dmarc"] = None

    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mandrill"]
    results["dkim"] = None
    for sel in dkim_selectors:
        try:
            r = requests.get(f"https://dns.google/resolve?name={sel}._domainkey.{domain}&type=TXT",
                             headers=UA, timeout=5)
            answers = r.json().get("Answer", [])
            if answers:
                results["dkim"] = f"selector={sel} → {answers[0]['data'][:80]}"
                break
        except Exception:
            pass

    score = 0
    if results["spf"]: score += 33
    if results["dmarc"]: score += 34
    if results["dkim"]: score += 33

    return {
        "domain": domain,
        "spf": results["spf"] or "❌ Не настроен",
        "dmarc": results["dmarc"] or "❌ Не настроен",
        "dkim": results["dkim"] or "❌ Не найден",
        "score": score,
        "grade": "A" if score == 100 else "B" if score >= 66 else "C" if score >= 33 else "F",
        "risk": "Низкий" if score == 100 else "Средний" if score >= 66 else "Высокий" if score >= 33 else "Критический",
    }


# ================= 5. ПРОВЕРКА ПАРОЛЕЙ (УГЛУБЛЁННАЯ) =================

COMMON_PATTERNS = [
    r"^[a-z]+$", r"^[A-Z]+$", r"^[0-9]+$",
    r"^(.)\1+$", r"^(01|12|23|34|45|56|67|78|89|90)+",
    r"^(qwerty|password|123456|abc123|letmein|admin|welcome)",
]


def analyze_password(password: str) -> dict:
    """Углублённый анализ пароля: энтропия, паттерны, рекомендации."""
    import math
    length = len(password)
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 33
    entropy = length * math.log2(charset) if charset else 0

    issues = []
    if length < 8: issues.append("⚠️ Менее 8 символов")
    if length < 12: issues.append("ℹ️ Рекомендуется 12+ символов")
    if not re.search(r"[A-Z]", password): issues.append("⚠️ Нет заглавных букв")
    if not re.search(r"[a-z]", password): issues.append("⚠️ Нет строчных букв")
    if not re.search(r"[0-9]", password): issues.append("⚠️ Нет цифр")
    if not re.search(r"[^a-zA-Z0-9]", password): issues.append("⚠️ Нет спецсимволов")
    for pat in COMMON_PATTERNS:
        if re.match(pat, password):
            issues.append("⚠️ Распространённый паттерн")
            break

    strength = (
        "ОЧЕНЬ СЛАБЫЙ" if entropy < 28 else
        "СЛАБЫЙ" if entropy < 36 else
        "СРЕДНИЙ" if entropy < 50 else
        "СИЛЬНЫЙ" if entropy < 65 else
        "ОЧЕНЬ СИЛЬНЫЙ"
    )

    return {
        "length": length,
        "charset_size": charset,
        "entropy_bits": round(entropy, 1),
        "strength": strength,
        "issues": issues,
        "safe": entropy >= 50 and len(issues) == 0,
    }


# ================= 6. ПРОВЕРКА ФАЙЛА/ХЕША НА ВИРУСЫ =================

def check_hash(hash_val: str) -> dict:
    """Проверка SHA-256/MD5 хеша через MalwareBazaar (бесплатный)."""
    hash_val = hash_val.strip().lower()
    if not re.match(r"^[a-f0-9]{32,64}$", hash_val):
        return {"error": "Не похоже на хеш (нужен MD5/SHA-256/SHA-1)"}
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_val},
            headers=UA, timeout=15,
        )
        data = r.json()
        if data.get("query_status") == "hash_not_found":
            return {"hash": hash_val, "status": "ЧИСТО (не найден в базе вредоносов)"}
        if data.get("query_status") == "ok":
            results = data.get("data", [])
            if results:
                item = results[0]
                return {
                    "hash": hash_val,
                    "status": "🚨 ВРЕДОНОСНЫЙ",
                    "name": item.get("signature", "?"),
                    "type": item.get("file_type", "?"),
                    "tags": item.get("tags", []),
                    "first_seen": item.get("first_seen", "?"),
                }
        return {"hash": hash_val, "status": "Неизвестно", "raw": data.get("query_status", "?")}
    except Exception as e:
        return {"hash": hash_val, "status": "Ошибка", "error": str(e)}


# ================= 7. WHOIS БЫСТРЫЙ =================

def quick_whois(domain: str) -> dict:
    """Быстрый WHOIS через rdap.org."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=10)
        if r.status_code != 200:
            return {"error": "Домен не найден"}
        d = r.json()
        events = {}
        for e in d.get("events", []):
            events[e.get("eventAction")] = e.get("eventDate")
        nameservers = [n.get("ldhName") for n in d.get("nameservers", [])]
        statuses = d.get("status", [])

        registrar = "?"
        for ent in (d.get("entities") or []):
            vcard = (ent.get("vcardArray") or [[], []])[1]
            for prop in vcard:
                if isinstance(prop, list) and prop[0] == "fn":
                    registrar = prop[3] if len(prop) > 3 else prop[2]
                    break
            if registrar != "?":
                break

        return {
            "domain": domain,
            "registrar": registrar,
            "created": events.get("registration"),
            "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "nameservers": nameservers,
            "statuses": statuses,
        }
    except Exception as e:
        return {"error": str(e)}


# ================= 8. ПРОВЕРКА СЕТИ (DNS OVER HTTPS) =================

def full_dns_check(domain: str) -> dict:
    """Полный DNS-аудит: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    results = {}
    for rt in record_types:
        try:
            r = requests.get(f"https://dns.google/resolve?name={domain}&type={rt}",
                             headers=UA, timeout=5)
            answers = r.json().get("Answer", [])
            if answers:
                results[rt] = [a.get("data") for a in answers[:10]]
        except Exception:
            pass
    return {"domain": domain, "records": results}


# ================= 9. ПРОВЕРКА EMAIL НА ВАЛИДНОСТЬ =================

def validate_email(email: str) -> dict:
    """Проверка email: синтаксикс, MX-записи, disposable-домены."""
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"email": email, "valid": False, "reason": "Неверный формат"}

    domain = email.split("@")[1].lower()

    DISPOSABLE = {"tempmail.com", "throwaway.com", "guerrillamail.com",
                  "mailinator.com", "10minutemail.com", "yopmail.com",
                  "guerrillamailblock.com", "sharklasers.com",
                  "dispostable.com", "throwaway.email", "temp-mail.org"}

    disposable = domain in DISPOSABLE

    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=MX",
                         headers=UA, timeout=5)
        mx = r.json().get("Answer", [])
        has_mx = bool(mx)
    except Exception:
        has_mx = False

    return {
        "email": email,
        "valid": has_mx,
        "has_mx": has_mx,
        "disposable": disposable,
        "warning": "⚠️ Временный почтовый сервис!" if disposable else None,
    }


# ================= 10. АВТОМАТИЧЕСКИЙ АУДИТ (всё сразу) =================

def full_audit(domain_or_url: str) -> dict:
    """Полный аудит: SSL + безопасность + DNS + DMARC + WHOIS."""
    domain = domain_or_url.replace("https://", "").replace("http://", "").split("/")[0]
    url = domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}"

    return {
        "domain": domain,
        "ssl": check_ssl(domain),
        "site_security": check_site_security(url),
        "email_security": check_email_security(domain),
        "whois": quick_whois(domain),
        "dns": full_dns_check(domain),
    }


# ================= 11. ЧТО ДЕЛАТЬ ПРИ АТАКЕ (ПЛАН ДЕЙСТВИЙ) =================

ATTACK_PLAYBOOK = {
    "ddos": (
        "🔴 **ТЕБЯ ДДОСЯТ**\n"
        "Что делать:\n"
        "1. Ничего не отключай на VPS — включи сбор логов (nginx/apache)\n"
        "2. Запиши IP атакующих из логов (обычно много адресов)\n"
        "3. Проверь каждый IP: /reputation <ip>\n"
        "4. Свяжись с хостингом/провайдером, требуй filter (null-route) и логи\n"
        "5. Включи анти-ДДоС: Cloudflare free / DDoS-Guard / Qrator\n"
        "6. Сохрани всё в кейс: /evidence text <отчёт>\n"
        "7. Обратись в техподдержку площадки + полицию (ст. 272 УК + 273)\n"
        "\nДоказательства: логи с таймстемпами, список IP = улики."
    ),
    "doxxing": (
        "🔴 **ТЕБЯ ДОКСЯТ (слили данные)**\n"
        "Что делать:\n"
        "1. Сфоткай/сохрани всё, где всплыл твой адрес/паспорт: /evidence url <ссылка>\n"
        "2. Добавь все свои email в /watch add — узнаешь новые утечки первым\n"
        "3. Проверь пароли: /pass <старый пароль>, смени всё на /strength-надёжные\n"
        "4. Включи 2FA везде, где есть\n"
        "5. Подай жалобу площадке: /report <платформа> <ссылка> <что слили>\n"
        "6. При угрозе жизни/имуществу — сразу полиция, не жди.\n"
        "\nВ РФ докс на грани: разглашение персональных данных + угрозы = ст. 137, 119 УК."
    ),
    "swatting": (
        "🔴 **СВАТЯТ (фальшивые вызовы спецслужб)**\n"
        "Что делать:\n"
        "1. Не паникуй. Собери доказательства угроз: /evidence text <сообщения>\n"
        "2. Сохраняй ВСЕ сообщения с угрозами/адресом\n"
        "3. /report в площадку + /scan <user_id> сваттера\n"
        "4. Зафиксируй время каждого звонка/сообщения (для МВД)\n"
        "5. Напиши заявление в полицию: статья 128.1 УК (клевета/заведомо ложный вызов)\n"
        "6. Позвони в своё МВД заранее и предупреди о фальшивках — сваттеры блокируются\n"
        "\nКлюч: ВСЁ фиксируется с SHA-256, ты защищён юридически."
    ),
    "hack": (
        "🔴 **ВЗЛОМАЛИ АККАУНТ/ПОЧТУ**\n"
        "Что делать:\n"
        "1. Немедленно смени пароль через другую сеть/устройство\n"
        "2. /pass <старый> → подтверди утечку, /strength <новый>\n"
        "3. Выпиши все активные сессии (где менял, почта, TG) и заверши чужие\n"
        "4. Проверь, какие данные могли утечь: /watch add <email>\n"
        "5. Сохрани подозрительные входы как доказательства\n"
        "6. При взломе соцсети верни доступ через официальный recovery\n"
        "7. Обратись в полицию: ст. 272 УК (неправомерный доступ)"
    ),
    "phishing": (
        "🟠 **ПРИСЛАЛИ ФИШИНГОВУЮ ССЫЛКУ**\n"
        "Что делать:\n"
        "1. НЕ открывай и НЕ вводи пароли\n"
        "2. /urlcheck <ссылка> — проверь опасность до открытия\n"
        "3. Проверь отправителя по /scan <user_id>\n"
        "4. Провайдер/банк не пишет «скорее!» — это точно скам\n"
        "5. Проверь, ввели ли данные уже где-то: /pass <пароль>\n"
        "6. Дай ссылку на фишинг = это твоя улика против мошенника"
    ),
}

ATTACK_ALIASES = {
    "ddos": "ddos", "ддoc": "ddos", "ддос": "ddos", "dos": "ddos",
    "дoxxing": "doxxing", "докс": "doxxing", "доксинг": "doxxing", "слив": "doxxing",
    "swatting": "swatting", "сват": "swatting", "сватинг": "swatting",
    "hack": "hack", "взлом": "hack", "взломали": "hack",
    "phishing": "phishing", "фишинг": "phishing", "скам": "phishing",
}


def attack_playbook(attack: str) -> str:
    key = ATTACK_ALIASES.get(attack.lower().strip())
    if not key:
        return "Не понял тип атаки. Примеры: ddos, доксинг, сватинг, взлом, фишинг"
    return ATTACK_PLAYBOOK[key]


# ================= 12. РЕПУТАЦИЯ IP (AbuseIPDB) =================

def ip_reputation(ip: str, api_key: str = "") -> dict:
    """Проверка IP в базе жалоб AbuseIPDB (нужен бесплатный ключ)."""
    if not api_key:
        return {"error": "Нужен ключ AbuseIPDB (бесплатный) — впиши в config.py: https://www.abuseipdb.com/register"}
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            headers={"Key": api_key, "Accept": "application/json", "User-Agent": "JusticeBot"},
            timeout=12,
        )
        d = r.json().get("data", {})
        if not d:
            return {"error": "Нет данных"}
        reports = d.get("reports", [])[:5]
        return {
            "ip": d.get("ipAddress"),
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode") or d.get("countryName") or "?",
            "usage": d.get("usageType", "?"),
            "isp": d.get("isp", "?"),
            "total_reports": d.get("numReports", 0),
            "whitelisted": d.get("isWhitelisted"),
            "reports": [f"- {x.get('countryCode')} | {x.get('categoryName', '?')} | {x.get('comment','')[:60]}" for x in reports],
        }
    except Exception as e:
        return {"error": str(e)}
