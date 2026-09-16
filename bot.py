import asyncio
import logging

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import BotCommand, ErrorEvent, Message
from aiogram.exceptions import TelegramBadRequest

import config
import cybersec
import evidence
import hunter
import osint
import protector
import reporter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

bot = Bot(token=config.BOT_TOKEN)
dp = Dispatcher()
router = Router()

OWNER = config.OWNER_ID

HELP_TEXT = (
    "🛡️ Justice Bot — все команды:\n\n"
    "=== ОСИНТ-ПРОВЕРКИ ===\n"
    "  /username <ник> — поиск юзера на 10 платформах\n"
    "  /ip <IP> — гео и провайдер из открытых реестров\n"
    "  /email <email> — утечки по HIBP\n"
    "  /domain <домен> — RDAP: владелец, сроки\n"
    "  /dns <домен> [тип] — DNS-записи\n"
    "  /site <url> — статус, заголовки, хеш контента\n\n"
    "=== КИБЕР-ЗАЩИТА ===\n"
    "  /pass <пароль> — проверка по утечкам\n"
    "  /strength <пароль> — анализ энтропии и надёжности\n"
    "  /urlcheck <url> — анализ на фишинг\n"
    "  /ssl <домен> — SSL/TLS сертификат\n"
    "  /seccheck <url> — HTTP-заголовки безопасности\n"
    "  /dmarc <домен> — email-защита: SPF/DKIM/DMARC\n"
    "  /audit <домен> — полный аудит (SSL+DNS+DMARC+Security)\n"
    "  /hashcheck <SHA256/MD5> — проверка файла на вирусы\n"
    "  /validate <email> — валидность + disposable-проверка\n"
    "  /whois <домен> — быстрый WHOIS\n\n"
    "=== ПРИ РЕАЛЬНОЙ АТАКЕ ===\n"
    "  /protect <ddos|доксинг|сватинг|взлом|фишинг> — план действий\n"
    "  /reputation <ip> — репутация IP атакующего (база жалоб)\n"
    "  /netcheck — аудит открытых портов своей машины\n\n"
    "=== ДОСЬЕ / ЛОГИ ===\n"
    "  /dossier <ник> — полное досье: все платформы + риск + кейс\n"
    "  /trace <ip> — гео + репутация IP (трассировка)\n"
    "  /logscan <путь> — поиск DDoS в access.log своего сервера\n"
    "  /export <case> — готовое заявление в полицию с хешем\n"
    "  /monitor — авто-слежка за угрозами в чатах (вкл/выкл)\n\n"
    "=== ПО ПОЛЬЗОВАТЕЛЮ ===\n"
    "  /scan <user_id> [ip] — карточка юзера\n"
    "  /scan text <текст> — проверка на угрозы\n\n"
    "=== ЗАЩИТА ОТ УТЕЧЕК ===\n"
    "  /watch add <email> [кто] — под наблюдение\n"
    "  /watch remove / list / check\n\n"
    "=== ДОКАЗАТЕЛЬСТВА ===\n"
    "  /evidence <user_id> — зафиксировать профиль\n"
    "  /evidence text <текст> — сохранить текст\n"
    "  /evidence url <url> — снимок сайта\n"
    "  /evidence cases / verify <case>\n\n"
    "=== ЖАЛОБЫ ===\n"
    "  /report <платформа> <ссылка> <детали>\n"
    "  /report links — официальные ссылки репортов"
)


def parse_args(command) -> str:
    return (command.args or "").strip()


async def reply(message: Message, text: str):
    try:
        await message.answer(text)
    except TelegramBadRequest as e:
        logging.error(f"reply fail: {e}")


def is_owner(message: Message) -> bool:
    return message.from_user.id == OWNER


async def guard(message: Message) -> bool:
    if message.from_user.id == OWNER:
        return True
    await message.answer("⛔ Только владелец бота!")
    return False


# ================= Меню команд =================

COMMANDS_MENU = [
    BotCommand(command="start", description="Меню команд"),
    BotCommand(command="username", description="Поиск ника на платформах"),
    BotCommand(command="ip", description="Инфо по IP"),
    BotCommand(command="pass", description="Проверка пароля по утечкам"),
    BotCommand(command="strength", description="Надёжность пароля"),
    BotCommand(command="domain", description="RDAP инфо о домене"),
    BotCommand(command="site", description="Анализ сайта"),
    BotCommand(command="ssl", description="Проверка SSL-сертификата"),
    BotCommand(command="urlcheck", description="Анализ URL на фишинг"),
    BotCommand(command="seccheck", description="Безопасность HTTP-заголовков"),
    BotCommand(command="dmarc", description="Email-защита домена"),
    BotCommand(command="audit", description="Полный аудит домена"),
    BotCommand(command="hashcheck", description="Проверка файла на вирусы"),
    BotCommand(command="validate", description="Валидность email"),
    BotCommand(command="whois", description="Быстрый WHOIS"),
    BotCommand(command="protect", description="План действий при атаке"),
    BotCommand(command="reputation", description="Репутация IP в базах жалоб"),
    BotCommand(command="netcheck", description="Аудит своих открытых портов"),
    BotCommand(command="dossier", description="Полное досье на юзера"),
    BotCommand(command="trace", description="Трассировка IP (гео+репутация)"),
    BotCommand(command="logscan", description="Анализ access.log на DDoS"),
    BotCommand(command="export", description="Заявление с доказательствами"),
    BotCommand(command="monitor", description="Авто-мониторинг угроз вкл/выкл"),
    BotCommand(command="dns", description="DNS-записи"),
    BotCommand(command="scan", description="Карточка юзера"),
    BotCommand(command="watch", description="Защита от утечек"),
    BotCommand(command="evidence", description="Доказательства"),
    BotCommand(command="report", description="Жалобы и ссылки"),
]


# ================= Обработчик ошибок (чтобы бот не молчал) =================

@dp.error()
async def on_error(event: ErrorEvent):
    logging.exception("Ошибка при обработке апдейта", exc_info=event.exception)
    try:
        msg = event.update.message if event.update and getattr(event.update, "message", None) else None
        if msg:
            await msg.answer(f"❌ Внутренняя ошибка: {event.exception}")
    except Exception:
        pass


# ================= Старт =================

@router.message(CommandStart())
async def cmd_start(message: Message):
    if not await guard(message):
        return
    await reply(message, HELP_TEXT)


@router.message(Command("help"))
async def cmd_help(message: Message):
    if not await guard(message):
        return
    await reply(message, HELP_TEXT)


# ================= OSINT =================

@router.message(Command("username"))
async def cmd_username(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /username <ник>")
        return
    await reply(message, "🔎 Ищу по платформам...")
    try:
        results = osint.check_username(arg)
        out = [f"🔎 Ник: **{arg}**"]
        for name, status, url in results:
            mark = {"НАЙДЕН": "✅", "Свободен": "⬜"}.get(status, "❔")
            out.append(f"{mark} {name} — {status}")
        await reply(message, "\n".join(out))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("ip"))
async def cmd_ip(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /ip <IP>")
        return
    await reply(message, "🛰 Проверяю IP...")
    try:
        data = osint.lookup_ip(arg)
        if "error" in data:
            await reply(message, f"❌ {data['error']}")
            return
        await reply(message,
            f"🌐 **{data.get('query')}**\n"
            f"📍 {data.get('city', '?')}, {data.get('regionName', '?')}, {data.get('country', '?')}\n"
            f"🏢 Провайдер: {data.get('isp', '?')}\n"
            f"🕸 Организация: {data.get('org', '?')}\n"
            f"🛰 AS: {data.get('as', '?')}\n"
            f"✅ Данные из публичного реестра ip-api.com")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("email"))
async def cmd_email(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /email <email>")
        return
    if not config.HIBP_API_KEY:
        await reply(message, "Нужен ключ HIBP (бесплатный) — впиши в config.py: https://haveibeenpwned.com/API/Key")
        return
    try:
        breaches = osint.breach_check(arg, config.HIBP_API_KEY)
        if breaches and isinstance(breaches[0], dict) and "error" in breaches[0]:
            await reply(message, f"❌ {breaches[0]['error']}")
            return
        if breaches:
            await reply(message, "⚠️ Email найден в утечках:\n" + "\n".join(f"- {b}" for b in breaches))
        else:
            await reply(message, f"✅ Утечек по **{arg}** не найдено")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("domain"))
async def cmd_domain(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /domain <домен>")
        return
    await reply(message, "🌐 Проверяю домен...")
    try:
        data = osint.domain_info(arg)
        if "error" in data:
            await reply(message, f"❌ {data['error']}")
            return
        await reply(message,
            f"🌐 Домен **{data['domain']}**\n"
            f"🏢 Регистратор: {data.get('registrar', '?')}\n"
            f"📅 Создан: {data.get('created', '?')}\n"
            f"⏳ Истекает: {data.get('expires', '?')}\n"
            f"🔄 Обновлён: {data.get('updated', '?')}\n"
            f"🧭 NS: {', '.join(data.get('nameservers', [])) or '?'}\n"
            f"✅ Источник: открытый реестр RDAP")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("dns"))
async def cmd_dns(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /dns <домен> [тип] — тип бывает A, AAAA, MX, TXT, NS, CNAME")
        return
    parts = arg.split()
    domain, rtype = parts[0], (parts[1].upper() if len(parts) > 1 else "A")
    try:
        data = osint.dns_lookup(domain, rtype)
        if data and "error" in data[0]:
            await reply(message, f"❌ {data[0]['error']}")
            return
        lines = [f"🧭 DNS {rtype} для **{domain}**:"]
        for a in data[:15]:
            lines.append(f"- {a.get('data')}")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("site"))
async def cmd_site(message: Message, command=None):
    if not await guard(message):
        return
    url = parse_args(command)
    if not url:
        await reply(message, "Использование: /site <url>")
        return
    if not url.startswith("http"):
        url = "https://" + url
    await reply(message, "🔍 Анализирую сайт...")
    try:
        s = osint.site_snapshot(url)
        if "error" in s:
            await reply(message, f"❌ {s['error']}")
            return
        await reply(message,
            f"🔍 Анализ сайта:\n"
            f"Запрошен: {s['requested']}\n"
            f"Финальный URL: {s['final_url']}\n"
            f"Статус: {s['status']} | Переадресаций: {s['redirects']}\n"
            f"Заголовок: {s['title']}\n"
            f"Server: {s.get('server', '?')}\n"
            f"SHA-256 (контент): `{s['sha256']}`")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


async def fetch_user(user_id: str):
    """Пытается достать профиль юзера по ID (работает из лички)."""
    try:
        return await bot.get_chat(int(user_id))
    except Exception:
        return None


# ================= КИБЕР-ЗАЩИТА =================

@router.message(Command("pass"))
async def cmd_pass(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /pass <пароль>")
        return
    try:
        res = osint.password_breached(arg)
        an = cybersec.analyze_password(arg)
        lines = ["🔐 Анализ пароля:"]
        lines.append(f"Длина: {an['length']} | Энтропия: {an['entropy_bits']} бит")
        lines.append(f"Надёжность: **{an['strength']}**")
        if res["pwned"]:
            lines.append(f"🚨 В утечках: **{res['count']}** раз!")
        else:
            lines.append("✅ В утечках не найден")
        for issue in an["issues"]:
            lines.append(f"  {issue}")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("strength"))
async def cmd_strength(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /strength <пароль>")
        return
    try:
        an = cybersec.analyze_password(arg)
        lines = [
            f"🔐 Анализ надёжности:",
            f"Длина: {an['length']} символов",
            f"Размер алфавита: {an['charset_size']} типов",
            f"Энтропия: **{an['entropy_bits']} бит**",
            f"Оценка: **{an['strength']}**",
        ]
        for i in an["issues"]:
            lines.append(f"  {i}")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("urlcheck"))
async def cmd_urlcheck(message: Message, command=None):
    if not await guard(message):
        return
    url = parse_args(command)
    if not url:
        await reply(message, "Использование: /urlcheck <url>")
        return
    await reply(message, "🔍 Проверяю URL...")
    try:
        res = cybersec.analyze_url(url)
        lines = [
            f"🔗 Анализ URL: **{res['url']}**",
            f"Домен: {res['domain']}",
            f"Оценка: **{res['level']}** (рейтинг {res['score']}/100)",
        ]
        lines += res["flags"] if res["flags"] else ["✅ Подозрений нет"]
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("ssl"))
async def cmd_ssl(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /ssl <домен>")
        return
    await reply(message, "🔒 Проверяю SSL...")
    try:
        res = cybersec.check_ssl(arg)
        if not res["valid"]:
            await reply(message, f"❌ SSL: {res.get('error', 'неизвестно')}")
            return
        lines = [
            f"🔒 SSL-сертификат **{res['host']}**",
            f"Валидный: ✅",
            f"Издатель: {res['issuer']}",
            f"Имя: {res['subject']}",
            f"Действует с: {res['not_before']}",
            f"Действует до: {res['not_after']}",
            f"Осталось: {res['days_left']} дней",
            f"Протокол: {res['protocol']}",
        ]
        if res.get("warning"): lines.append(res["warning"])
        if res.get("danger"): lines.append(res["danger"])
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("seccheck"))
async def cmd_seccheck(message: Message, command=None):
    if not await guard(message):
        return
    url = parse_args(command)
    if not url:
        await reply(message, "Использование: /seccheck <url>")
        return
    await reply(message, "🛡️ Проверяю заголовки...")
    try:
        res = cybersec.check_site_security(url)
        if "error" in res:
            await reply(message, f"❌ {res['error']}")
            return
        lines = [
            f"🛡️ Безопасность **{res['url']}**",
            f"Статус: {res['status']} | SSL: {'✅' if res['ssl'] else '❌'}",
            f"Server: {res['server']} | Powered: {res.get('powered_by','?')}",
            f"Оценка: **{res['security_grade']}** ({res['score']}%)",
            f"\n--- Есть ({len(res['found'])}) ---",
        ] + res["found"] + [f"\n--- Нет ({len(res['missing'])}) ---"] + res["missing"]
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("dmarc"))
async def cmd_dmarc(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /dmarc <домен>")
        return
    await reply(message, "📧 Проверяю email-защиту...")
    try:
        res = cybersec.check_email_security(arg)
        lines = [
            f"📧 Email-защита **{res['domain']}**",
            f"SPF: {res['spf']}",
            f"DMARC: {res['dmarc']}",
            f"DKIM: {res['dkim']}",
            f"Оценка: **{res['grade']}** ({res['score']}%) | Риск: {res['risk']}",
        ]
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("audit"))
async def cmd_audit(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /audit <домен>")
        return
    await reply(message, "🔍 Полный аудит... (это займёт ~10 сек)")
    try:
        r = cybersec.full_audit(arg)
        ssl_ = r["ssl"]
        sec = r["site_security"]
        email = r["email_security"]
        whois = r["whois"]
        dns = r["dns"]

        lines = [
            f"🔍 **ПОЛНЫЙ АУДИТ {r['domain']}**",
            "",
            f"🔒 SSL: {'✅ ' + ssl_.get('issuer','') + ' (' + str(ssl_.get('days_left','?')) + ' дн)' if ssl_.get('valid') else '❌ ' + ssl_.get('error','?')}",
            f"🛡️ Security: {sec.get('security_grade','?')} ({sec.get('score','?')}%)",
            f"📧 Email: {email.get('grade','?')} | SPF={'✅' if 'Не настроен' not in email.get('spf','') else '❌'} DMARC={'✅' if 'Не настроен' not in email.get('dmarc','') else '❌'} DKIM={'✅' if 'Не' not in email.get('dkim','') else '❌'}",
        ]
        if whois and "error" not in whois:
            lines.append(f"📋 Регистратор: {whois.get('registrar','?')} | Создан: {whois.get('created','?')[:10] if whois.get('created') else '?'}")
        if dns.get("records"):
            lines.append(f"🧭 DNS: {', '.join(dns['records'].keys())}")

        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("hashcheck"))
async def cmd_hashcheck(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /hashcheck <SHA-256 или MD5 хеш>")
        return
    await reply(message, "🔍 Проверяю хеш...")
    try:
        res = cybersec.check_hash(arg)
        lines = [f"🔍 Проверка хеша: `{res.get('hash', arg)}`"]
        lines.append(f"Статус: **{res.get('status', '?')}**")
        for k in ("name", "type", "tags", "first_seen", "error"):
            if k in res and res[k]:
                lines.append(f"{k}: {res[k]}")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("validate"))
async def cmd_validate(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /validate <email>")
        return
    try:
        res = cybersec.validate_email(arg)
        lines = [
            f"📧 Проверка **{res['email']}**",
            f"Валидный: {'✅' if res['valid'] else '❌'}",
            f"MX-запись: {'✅' if res['has_mx'] else '❌'}",
        ]
        if res.get("warning"):
            lines.append(res["warning"])
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("whois"))
async def cmd_whois(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /whois <домен>")
        return
    await reply(message, "🔍 WHOIS...")
    try:
        res = cybersec.quick_whois(arg)
        if "error" in res:
            await reply(message, f"❌ {res['error']}")
            return
        lines = [
            f"📋 WHOIS **{res['domain']}**",
            f"Регистратор: {res.get('registrar', '?')}",
            f"Создан: {res.get('created', '?')}",
            f"Истекает: {res.get('expires', '?')}",
            f"NS: {', '.join(res.get('nameservers', []))}",
        ]
        if res.get("statuses"):
            lines.append("Статусы: " + ", ".join(res["statuses"][:4]))
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


# ================= КИБЕР-ЗАЩИТА · РЕАЛЬНЫЕ АТАКИ =================

@router.message(Command("protect"))
async def cmd_protect(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /protect <ddos | доксинг | сватинг | взлом | фишинг>")
        return
    await reply(message, cybersec.attack_playbook(arg))


@router.message(Command("reputation"))
async def cmd_reputation(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /reputation <ip>")
        return
    if not config.ABUSEIPDB_KEY:
        await reply(message, "Нужен ключ AbuseIPDB (бесплатный). Впиши в config.py:\nhttps://www.abuseipdb.com/register — 1 клик, 1000 запросов/день бесплатно.")
        return
    await reply(message, "🔍 Проверяю репутацию IP...")
    try:
        r = cybersec.ip_reputation(arg, config.ABUSEIPDB_KEY)
        if "error" in r:
            await reply(message, f"❌ {r['error']}")
            return
        lines = [
            f"⚠️ Репутация IP **{r['ip']}**",
            f"Скор: **{r['abuse_score']}/100**",
            f"Жалоб за 90 дней: {r['total_reports']}",
            f"Страна: {r['country']} | Использование: {r['usage']}",
        ]
        if r["total_reports"]:
            lines.append("Последние жалобы:")
            lines += r["reports"]
        else:
            lines.append("Чистый IP по базе жалоб.")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("netcheck"))
async def cmd_netcheck(message: Message, command=None):
    if not await guard(message):
        return
    await reply(message, "🔍 Смотрю открытые порты...")
    try:
        import subprocess
        out = subprocess.run(["netstat", "-an"], capture_output=True, text=True,
                             shell=True).stdout
        lines_all = [l.strip() for l in out.splitlines() if "LISTENING" in l.upper()
                     and ("0.0.0.0:" in l or "127.0.0.1:" in l or "[::]:" in l)]
        if not lines_all:
            await reply(message, "✅ Открытых слушающих портов не нашёл")
            return
        parts = [
            "🖥 Открытые порты на этой машине:",
            "⚠️ Если порт открыт наружу (0.0.0.0) и ты его не открывал — проверь!",
        ]
        for l in lines_all[:20]:
            parts.append(f"`{l}`")
        ports = [l.split(":")[-1].split()[0] for l in lines_all]
        parts.append(f"\nВсего: {len(lines_all)} порт(ов)")
        await reply(message, "\n".join(parts))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


# ================= ДОСЬЕ / ТРАССИРОВКА / АНАЛИЗ ЛОГОВ =================

@router.message(Command("dossier"))
async def cmd_dossier(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /dossier <ник>")
        return
    await reply(message, f"🕵️ Собираю досье на **{arg}**... (это ~10 сек)")
    try:
        d = hunter.build_dossier(arg)
        await reply(message,
            f"🕵️ **ДОСЬЕ: {d['nickname']}**\n"
            f"Активен на: {d['active_on']}\n"
            f"Вывод: **{d['risk']}**\n"
            f"Кейс: `{d['record']['case']}`\n"
            f"SHA-256: `{d['record']['sha256'][:24]}…`\n\n"
            "Полный текст: /evidence text из кейса, экспорт: /export <case>")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("trace"))
async def cmd_trace(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /trace <ip>")
        return
    await reply(message, "🛰 Трассирую IP...")
    try:
        t = hunter.trace_ip(arg, config.ABUSEIPDB_KEY)
        lines = [f"🛰 Трассировка **{t['ip']}**"]
        if t["geo"]:
            lines.append(f"📍 {t['geo'].get('city','?')}, {t['geo'].get('country','?')} | {t['geo'].get('isp','?')}")
        if t["reputation"]:
            lines.append(f"⚠️ Жалоб: {t['reputation']['total_reports']} | Скор: {t['reputation']['abuse_score']}/100")
        elif not config.ABUSEIPDB_KEY:
            lines.append("(репутация: впиши ABUSEIPDB_KEY в config.py)")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("logscan"))
async def cmd_logscan(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /logscan <путь к access.log>")
        return
    await reply(message, "🔍 Анализирую лог...")
    try:
        r = hunter.analyze_access_log(arg)
        if "error" in r:
            await reply(message, f"❌ {r['error']}")
            return
        lines = [
            f"🔍 Анализ лога: `{r['file']}`",
            f"Строк: {r['total_lines']}",
        ]
        if r.get("anomaly"):
            label, ip, cnt = r["anomaly"]
            lines.append(f"{label}: **{ip}** — {cnt} запросов!")
        lines.append("")
        lines.append("Топ IP:")
        for ip, cnt in r["top_ips"][:6]:
            lines.append(f"  {ip} ({cnt})")
        lines.append("")
        lines.append("Опасные пути / боты:")
        if r["attack_hits"]:
            for ip, ts, tag, ua, req in r["attack_hits"][:5]:
                lines.append(f"  {tag} {ip} {req}")
        else:
            lines.append("  Не найдено")
        await reply(message, "\n".join(lines))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("export"))
async def cmd_export(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование: /export <case_id> — готовое заявление с доказательством")
        return
    try:
        r = hunter.export_dossier(arg)
        if "error" in r:
            await reply(message, f"❌ {r['error']}")
            return
        txt = f"{r['report'][:4000]}"
        await reply(message, txt)
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


@router.message(Command("monitor"))
async def cmd_monitor(message: Message):
    if not await guard(message):
        return
    global _monitor_on
    _monitor_on = not _monitor_on
    state = "ВКЛЮЧЁН 🔴" if _monitor_on else "ВЫКЛЮЧЕН ⚪"
    await reply(message,
        f"Мониторинг угроз: **{state}**\n"
        "Бот следит за сообщениями в чатах, где он состоит.\n"
        "При угрозе/доксинге автоматически: сохраняет кейс с SHA-256 и шлёт тебе сюда.\n"
        "Управление: /monitor — вкл/выкл")


@router.message(F.text, ~F.text.startswith("/"))
async def auto_monitor(message: Message):
    if not _monitor_on:
        return
    if message.from_user.id == OWNER:
        return
    hits = osint.threat_words_in(message.text or "")
    if not hits:
        return
    rec = evidence.snapshot_user(
        message.from_user.full_name or "?",
        message.from_user.id,
        [message],
    )
    try:
        await message.reply(f"⚠️ Зафиксировано как угроза/докс: {', '.join(hits)}")
    except Exception:
        pass
    try:
        await bot.send_message(OWNER,
            f"🚨 **{message.from_user.full_name}** ({message.from_user.id}) в {message.chat.title or 'личке'}:\n"
            f"`{message.text[:200]}`\n"
            f"Кейс: `{rec['case']}`  SHA: `{rec['sha256'][:16]}…`")
    except Exception as e:
        logging.error(f"monitor: {e}")


_monitor_on = True

@router.message(Command("scan"))
async def cmd_scan(message: Message, command=None):
    if not await guard(message):
        return
    parts = parse_args(command).split()
    if not parts:
        await reply(message, "Использование:\n/scan <user_id> [ip]\n/scan text <текст для проверки>")
        return

    if parts[0] == "text":
        text = " ".join(parts[1:])
        hits = osint.threat_words_in(text)
        if hits:
            await reply(message, f"⚠️ Обнаружены признаки угроз/доксинга: {', '.join(hits)}\n\nСовет: сохрани доказательство — /evidence text <текст>")
        else:
            await reply(message, "✅ Подозрительных слов в тексте не найдено")
        return

    user_id = parts[0]
    ip = parts[1] if len(parts) > 1 else None
    u = await fetch_user(user_id)
    if not u or u.type != "private":
        await reply(message, f"❌ Не нашёл юзера {user_id}. Он должен хоть раз нажать /start у бота @Sunsower_bot (или вы в одном чате)")
        return

    rec = evidence.snapshot_user(
        u.full_name or "?",
        u.id,
        [type("M", (), {"content": f"@{u.username}" if u.username else "", "author": u.full_name})()],
    )

    lines = [
        f"🎯 **{u.full_name}**",
        f"ID: `{u.id}`",
        f"Ник: @{u.username}" if u.username else "Ник: —",
        f"Бот: {u.is_bot}",
        f"Кейс: `{rec['case']}`  SHA: `{rec['sha256'][:16]}…`",
    ]
    if ip:
        data = osint.lookup_ip(ip)
        if "error" not in data:
            lines.append(f"📍 {data.get('city', '?')}, {data.get('country', '?')} | {data.get('isp', '?')}")

    found = osint.check_username(u.username or u.full_name.replace(" ", ""))[:6]
    present = [n for n, st, url in found if st == "НАЙДЕН"]
    lines.append("🕵️ Активен на: " + (", ".join(present) or "—"))

    await reply(message, "\n".join(lines))


# ================= Защита =================

@router.message(Command("watch"))
async def cmd_watch(message: Message, command=None):
    if not await guard(message):
        return
    parts = parse_args(command).split(maxsplit=2)
    action = parts[0] if parts else ""
    try:
        if action == "add" and len(parts) >= 2:
            email, note = parts[1], (parts[2] if len(parts) > 2 else "")
            res = protector.add_watch(email, note)
            await reply(message,
                f"✅ **{email}** добавлен в watchlist (каждые {config.WATCH_INTERVAL_HOURS} ч проверится)"
                if res["added"] else f"ℹ️ **{email}** уже в списке")
        elif action == "remove" and len(parts) >= 2:
            ok = protector.remove_watch(parts[1])
            await reply(message, f"✅ Удалён: {parts[1]}" if ok else f"❌ Не в списке: {parts[1]}")
        elif action == "list":
            data = protector.load_watchlist()
            if not data:
                await reply(message, "Пусто. Добавь: /watch add <email> [кто]")
                return
            lines = ["📋 Watchlist:"]
            for item in data.values():
                known = ", ".join(item.get("known_breaches", [])) or "—"
                lines.append(f"- {item['email']} ({item.get('note', '?')}) — найдено: {known}")
            await reply(message, "\n".join(lines))
        elif action == "check":
            await reply(message, "🔍 Проверяю...")
            alerts = protector.check_watchlist(config.HIBP_API_KEY)
            if not alerts:
                await reply(message, "✅ Все эмейлы чистые или нет ключа HIBP")
                return
            for a in alerts:
                await reply(message, f"🚨 **{a['email']}** ({a['note']}) — НОВЫЕ: {', '.join(a['new'])}")
        else:
            await reply(message, "Использование:\n/watch add <email> [кто]\n/watch remove <email>\n/watch list\n/watch check")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


# ================= Доказательства =================

@router.message(Command("evidence"))
async def cmd_evidence(message: Message, command=None):
    if not await guard(message):
        return
    arg = parse_args(command)
    if not arg:
        await reply(message, "Использование:\n/evidence <user_id>\n/evidence text <текст>\n/evidence url <url>\n/evidence cases\n/evidence verify <case>")
        return

    try:
        # Проверка целостности
        if arg.split()[0] == "verify" and len(arg.split()) > 1:
            res = evidence.verify_case(arg.split()[1])
            if res["ok"]:
                await reply(message, f"✅ Кейс `{arg.split()[1]}` не изменён. Хеш совпадает.")
            else:
                await reply(message, f"❌ {res.get('reason', 'Кейс изменён!')}\nБыло: {res.get('recorded')}\nСтало: {res.get('current')}")
            return

        # Список кейсов
        if arg.split()[0] == "cases":
            cases = evidence.list_cases()
            if not cases:
                await reply(message, "Кейсов пока нет")
                return
            lines = [f"📁 {len(cases)} кейс(ов):"]
            for c in cases[:10]:
                lines.append(f"- `{c['case']}` | {c['meta'].get('target_name', '?')} | {c['meta']['messages']} msg")
            await reply(message, "\n".join(lines))
            return

        # Сохранить текст
        if arg.split()[0] == "text":
            text = " ".join(arg.split()[1:])
            if not text:
                await reply(message, "Покажи текст: /evidence text <тут текст>")
                return
            rec = evidence.save_case(f"text_{message.from_user.id}_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                                     {"target_name": "текст", "messages": len(text)}, text)
            await reply(message, f"📄 Текст сохранён\nКейс: `{rec['case']}`\nSHA-256: `{rec['sha256']}`")
            return

        # Снимок сайта
        if arg.split()[0] == "url":
            url = arg.split()[1] if len(arg.split()) > 1 else ""
            if not url.startswith("http"):
                url = "https://" + url
            s = osint.site_snapshot(url)
            if "error" in s:
                await reply(message, f"❌ {s['error']}")
                return
            body = f"URL: {s['requested']}\nФинальный: {s['final_url']}\nСтатус: {s['status']}\nЗаголовок: {s['title']}\nSHA-256: {s['sha256']}"
            rec = evidence.save_case(f"url_{message.from_user.id}_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                                     {"target_name": s["final_url"], "messages": 1}, body)
            await reply(message, f"📄 Снимок сайта сохранён ({s['status']})\nКейс: `{rec['case']}`\nSHA-256: `{rec['sha256']}`")
            return

        # Фиксация профиля юзера
        user_id = arg.split()[0]
        u = await fetch_user(user_id)
        if not u or u.type != "private":
            await reply(message, f"❌ Не нашёл юзера {user_id}. Он должен хоть раз нажать /start у бота (или вы в одном чате)")
            return
        rec = evidence.snapshot_user(
            u.full_name or "?",
            u.id,
            [type("M", (), {"content": f"@{u.username}" if u.username else "", "author": u.full_name})()],
        )
        await reply(message,
            f"📸 Зафиксирован **{u.full_name}**\n"
            f"Кейс: `{rec['case']}`\n"
            f"SHA-256: `{rec['sha256']}`\n"
            f"Время: `{rec['saved_at']}`")
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


# ================= Репорты =================

@router.message(Command("report"))
async def cmd_report(message: Message, command=None):
    if not await guard(message):
        return
    parts = parse_args(command).split(maxsplit=3)
    try:
        if parts and parts[0] == "links":
            lines = ["📮 Официальные каналы жалоб:"]
            for name, url in reporter.REPORT_LINKS.items():
                lines.append(f"- **{name}**: {url}")
            await reply(message, "\n".join(lines))
            return
        if len(parts) < 3:
            await reply(message, "Использование:\n/report <платформа> <ссылка> <детали> [доказательство]\n/report links")
            return
        platform, link, details = parts[:3]
        proof = parts[3] if len(parts) > 3 else ""
        await reply(message, reporter.report_template(platform.capitalize(), link, proof, details))
    except Exception as e:
        await reply(message, f"❌ Ошибка: {e}")


# ================= Фоновая реакция на незнакомые команды =================

@router.message(F.text.startswith("/"))
async def unknown_command(message: Message):
    if not await guard(message):
        return
    first = message.text.split()[0].lower()
    known = {f"/{c.command}" for c in COMMANDS_MENU} | {"/start", "/help"}
    if first in known:
        return
    await reply(message, "Не знаю такой команды. Смотри /start 👇")


# ================= Фоновый мониторинг =================

async def watch_background():
    while True:
        await asyncio.sleep(config.WATCH_INTERVAL_HOURS * 3600)
        if not config.HIBP_API_KEY or not OWNER:
            continue
        try:
            alerts = protector.check_watchlist(config.HIBP_API_KEY)
            for a in alerts:
                await bot.send_message(OWNER, f"🚨 **{a['email']}** ({a['note']}) — НОВЫЕ: {', '.join(a['new'])}")
        except Exception as e:
            logging.error(f"watch: {e}")


# ================= Запуск =================

async def main():
    dp.include_router(router)
    try:
        await bot.set_my_commands(COMMANDS_MENU)
        logging.info("Меню команд установлено")
    except Exception as e:
        logging.error(f"Меню: {e}")
    logging.info("Justice Bot (TG) запущен")
    await bot.delete_webhook(drop_pending_updates=True)
    asyncio.create_task(watch_background())
    await dp.start_polling(bot)


if __name__ == "__main__":
    if config.BOT_TOKEN.startswith("ВСТАВЬ"):
        print("⚠️  Сначала впиши BOT_TOKEN и OWNER_ID в config.py!")
    else:
        asyncio.run(main())