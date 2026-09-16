import collections
import json
import os
import re
from datetime import datetime

import cybersec
import evidence
import osint

# ============================================================
# "FSOCIETY" — БЕЛАЯ ВЕРСИЯ
# Всё, что делали в сериале, но легально:
# досье, анализ логов на DDoS, слежка за угрозами в чатах.
# ============================================================


# ================= 1. ПОЛНОЕ ДОСЬЕ НА ЮЗЕРА =================

def build_dossier(nickname: str) -> dict:
    """Собирает всё в один файл: платформы + домены + IP + риск."""
    nickname = osint.sanitize(nickname)
    parts = []

    parts.append(f"=== ДОСЬЕ: {nickname} ===")
    parts.append(f"Сформировано: {datetime.utcnow().isoformat(timespec='seconds')}Z")
    parts.append("")

    found = []
    for name, status, url in osint.check_username(nickname):
        mark = "НАЙДЕН" if status == "НАЙДЕН" else "нет"
        if status == "НАЙДЕН":
            found.append(name)
        parts.append(f"[{mark}] {name}: {url}")

    active = ", ".join(found) or "нет"
    parts.append("")
    parts.append(f"Активен на: {active}")
    parts.append(f"Всего платформ: {len(found)}/10")
    parts.append("")

    risk = "ЛЕГЕНДА: юзер не найден" if not found else \
           "СЛЕД: обнаружен на публичных площадках" if len(found) < 4 else \
           "ЦЕЛЬ: активный пользователь сети" if len(found) < 7 else \
           "ПОЛНАЯ ЛИЧНОСТЬ: живёт в интернете, легко вычислить"
    parts.append(f"Вывод: {risk}")

    body = "\n".join(parts)
    rec = evidence.save_case(f"dossier_{nickname}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                             {"target_name": nickname, "messages": len(parts)}, body)
    return {"nickname": nickname, "active_on": active, "risk": risk, "record": rec}


# ================= 2. АНАЛИЗ ЛОГОВ НА DDoS (на своём сервере) =================

DANGER_PATHS = ["/wp-login.php", "/admin", "/xmlrpc.php", "/.env", "/config.php",
                "/phpmyadmin", "/shell", "/cmd", "/login", "/?s=", "/api/v1/"]


def analyze_access_log(path: str) -> dict:
    """Читает access.log (nginx/apache) и ищет признаки атаки."""
    if not os.path.exists(path):
        return {"error": f"Файл не найден: {path}"}

    ip_counter = collections.Counter()
    path_counter = collections.Counter()
    status_counter = collections.Counter()
    user_agents = collections.Counter()
    attack_hits = []

    line_re = re.compile(
        r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(\w+) (\S+) (\S+)" (\d+) .*?"([^"]*)" "([^"]*)"'
    )

    total = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            total += 1
            m = line_re.match(line)
            if not m:
                continue
            ip, ts, method, req, proto, status, referer, ua = m.groups()
            ip_counter[ip] += 1
            status_counter[status] += 1
            if ua:
                ua_short = ua[:60]
                user_agents[ua_short] += 1
                if "curl" in ua.lower() or "python" in ua.lower() or "wget" in ua.lower():
                    attack_hits.append((ip, ts, "БОТ-агент:", ua_short, req))
            if req:
                p = req.split("?")[0].lower()
                path_counter[p[:80]] += 1
                if any(dp in p for dp in DANGER_PATHS):
                    attack_hits.append((ip, ts, "ОПАСНЫЙ путь:", "", req))

    top_ips = ip_counter.most_common(10)
    anomaly = None
    for ip, cnt in top_ips:
        if cnt > 200:
            anomaly = ("🚨 ВОЗМОЖЕН DDoS", ip, cnt)
            break
    if not anomaly:
        for ip, cnt in top_ips:
            if cnt > 50 and len(top_ips) > 3:
                anomaly = ("⚠️ ПОДОЗРЕНИЕ", ip, cnt)
                break

    return {
        "file": path,
        "total_lines": total,
        "parsed": sum(ip_counter.values()),
        "top_ips": top_ips,
        "statuses": status_counter.most_common(5),
        "top_paths": path_counter.most_common(5),
        "bot_agents": user_agents.most_common(5),
        "attack_hits": attack_hits[:10],
        "anomaly": anomaly,
    }


# ================= 3. ТРАССИРОВКА ПОДОЗРИТЕЛЬНОГО IP =================

def trace_ip(ip: str, abuse_key: str = "") -> dict:
    """Соединяет гео + репутацию + WHOIS-владельца подсети в досье."""
    geo = osint.lookup_ip(ip)
    rep = cybersec.ip_reputation(ip, abuse_key) if abuse_key else {"error": "нет ключа"}
    return {
        "ip": ip,
        "geo": geo if "error" not in geo else None,
        "reputation": rep if "error" not in rep else None,
    }


# ================= 4. ЭКСПОРТ ДОСЬЕ + ПРОВЕРКА =================

def export_dossier(case_id: str) -> dict:
    """Готовый текст для подачи в полицию/поддержку."""
    base = os.path.join(evidence.config.EVIDENCE_DIR, case_id)
    txt = os.path.join(base, "evidence.txt")
    if not os.path.exists(txt):
        return {"error": "Кейс не найден"}
    with open(txt, encoding="utf-8") as f:
        body = f.read()
    rec = evidence.verify_case(case_id)
    return {
        "case": case_id,
        "integrity_ok": rec.get("ok"),
        "sha256": rec.get("current"),
        "report": (
            "ЗАЯВЛЕНИЕ (ШАБЛОН)\n"
            "Кому: в дежурную часть / техподдержку площадки\n"
            "От кого: <ваши ФИО>\n"
            "Тема: противоправные действия против меня\n\n"
            "На дату {дата} в отношении меня совершены действия: "
            "(угрозы / разглашение данных / вызов служб / доступ к системе).\n\n"
            "ДОКАЗАТЕЛЬСТВА: файлы с SHA-256 целостностью:\n"
            f"Кейс: {case_id}\n"
            f"SHA-256: {rec.get('current')}\n\n"
            "Содержимое:\n"
            f"{body}\n\n"
            "Прошу: восстановить доступ / привлечь виновных к ответственности, "
            "уведомить меня о результате. Файлы с хешами прилагаю."
        ),
    }