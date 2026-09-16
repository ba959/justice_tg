import hashlib
import json
import re
import urllib.request

import requests

# ================= Публичные проверки (легальный OSINT) =================

# Список платформ: имя -> шаблон профиля
PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Telegram": "https://t.me/{}",
    "YouTube": "https://youtube.com/@{1}",
    "Twitch": "https://twitch.tv/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Discord": "https://discord.com/users/{}",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)


def sanitize(value: str) -> str:
    return re.sub(r"[^\w@.\-]", "", value)[:64]


def check_username(username: str) -> list:
    """Ищем ник на публичных платформах через HEAD-запросы."""
    username = sanitize(username)
    results = []
    UA = {"User-Agent": "Mozilla/5.0 (JusticeBot)"}
    for name, url_tpl in PLATFORMS.items():
        tmpl = "https://youtube.com/@{}" if name == "YouTube" else url_tpl
        url = tmpl.format(username)
        try:
            req = urllib.request.Request(url, headers=UA, method="GET")
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status in (200, 203):
                    results.append((name, "НАЙДЕН", url))
        except urllib.error.HTTPError as e:
            if e.code in (404, 410, 451):
                results.append((name, "Свободен", url))
        except Exception:
            results.append((name, "?", url))
    return results


def lookup_ip(ip: str) -> dict:
    """Через публичный ip-api.com (все данные из открытых реестров)."""
    if not IP_RE.match(ip):
        return {"error": "Не похоже на IP-адрес"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data = r.json()
        return data if data.get("status") == "success" else {"error": data.get("message", "?"), **data}
    except Exception as e:
        return {"error": str(e)}


def breach_check(email: str, api_key: str = "") -> list:
    """Проверка утечек через HaveIBeenPwned (официальный API)."""
    if not EMAIL_RE.match(email):
        return [{"error": "Не похоже на email"}]
    if not api_key:
        return [{"error": "Нет API-ключа HIBP для этого. Впиши вызывает config.HIBP_API_KEY"}]
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "user-agent": "JusticeBot"},
            timeout=10,
        )
        if r.status_code == 200:
            return [b["Name"] for b in r.json()]
        if r.status_code == 404:
            return []
        return [{"error": f"HTTP {r.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


def password_breached(password: str) -> dict:
    """Проверка пароля по k-anonymity API (бесплатно, без ключа)."""
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        if r.status_code != 200:
            return {"pwned": False, "detail": f"HTTP {r.status_code}"}
        for line in r.text.splitlines():
            s, count = line.split(":")
            if s == suffix:
                return {"pwned": True, "count": int(count), "hash_prefix": prefix}
        return {"pwned": False}
    except Exception as e:
        return {"pwned": False, "detail": str(e)}


# ============ Дополнительные легальные проверки ============

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def domain_info(domain: str) -> dict:
    """Информация о домене через RDAP (открытый реестр регистраторов)."""
    domain = sanitize(domain).lower()
    if not DOMAIN_RE.match(domain):
        return {"error": "Не похоже на домен. Пример: example.com"}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}",
                         headers={"User-Agent": "JusticeBot"}, timeout=12)
        if r.status_code != 200:
            return {"error": f"Домен не найден в RDAP (HTTP {r.status_code})"}
        d = r.json()
        events = {e.get("eventAction"): e.get("eventDate", "?") for e in d.get("events", [])}
        nameservers = [n.get("ldhName", "?") for n in d.get("nameservers", [])]

        registrar = "?"
        entities = d.get("entities") or []
        if entities:
            vcard = (entities[0].get("vcardArray") or [[], []])[1]
            for prop in vcard:
                if isinstance(prop, list) and prop and prop[0] in ("fn", "org"):
                    registrar = prop[3] if len(prop) > 3 else prop[2]
                    break
        return {
            "domain": domain,
            "registrar": registrar,
            "created": events.get("registration"),
            "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "nameservers": nameservers,
            "status": d.get("status", []),
            "source": "https://rdap.org (открытые данные регистратора)",
        }
    except Exception as e:
        return {"error": str(e)}


def dns_lookup(domain: str, record_type: str = "A") -> list:
    """DNS-запрос через публичный DNS Google. Типы: A, AAAA, MX, TXT, NS, CNAME."""
    domain = sanitize(domain).lower()
    try:
        r = requests.get(
            f"https://dns.google/resolve?name={domain}&type={record_type}",
            headers={"User-Agent": "JusticeBot"}, timeout=8,
        )
        j = r.json()
        answers = j.get("Answer", [])
        if not answers:
            return [{"error": "записей нет"}]
        return [{"type": a.get("type"), "data": a.get("data")} for a in answers]
    except Exception as e:
        return [{"error": str(e)}]


def site_snapshot(url: str) -> dict:
    """Снимок сайта: финальный URL после переадресаций, статус, заголовок, SHA-256."""
    try:
        r = requests.get(url, timeout=12, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (JusticeBot)"})
        body = r.text[:200_000]
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = (m.group(1).strip()[:120] if m else "не найден")
        return {
            "requested": url,
            "final_url": r.url,
            "status": r.status_code,
            "redirects": len(r.history),
            "title": title,
            "server": r.headers.get("Server", "?"),
            "sha256": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest(),
            "size": len(body),
        }
    except Exception as e:
        return {"error": str(e), "requested": url}


def threat_words_in(text: str) -> list:
    """Ищет в тексте признаки доксинга/угроз (для предупреждений)."""
    words = ["адрес", "сват", "ложил", "солью", "слил", "паспорт", "пробив",
             "прозвон", "голову", "убью", "найду", "уберу", "семью", "родителей"]
    low = text.lower()
    return sorted({w for w in words if w in low})