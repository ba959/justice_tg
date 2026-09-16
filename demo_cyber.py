import sys, os
sys.path.insert(0, os.getcwd())
import cybersec
import json

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

print("=== 1. АНАЛИЗ URL НА ФИШИНГ ===")
r = cybersec.analyze_url("http://google.com")
print(f"  google.com: {r['level']} ({r['score']}/100)")
r2 = cybersec.analyze_url("http://login-verify-bank.xyz/account/update")
print(f"  подозрительный: {r2['level']} ({r2['score']}/100)")
print("  flags:", len(r2['flags']))

print("\n=== 2. SSL EXPIRE ===")
s = cybersec.check_ssl("google.com")
print(f"  google.com: valid={s['valid']}, issuer={s.get('issuer')}, дней={s.get('days_left')}")

print("\n=== 3. SECURITY HEADERS ===")
sc = cybersec.check_site_security("https://github.com")
print(f"  github: grade={sc.get('security_grade')}, score={sc.get('score')}%")

print("\n=== 4. EMAIL SECURITY ===")
em = cybersec.check_email_security("google.com")
print(f"  google: grade={em['grade']}, SPF={'ok' if em['spf'] != '❌ Не настроен' else 'нет'}, DMARC={'ok' if em['dmarc'] != '❌ Не настроен' else 'нет'}")

print("\n=== 5. PASSWORD STRENGTH ===")
p1 = cybersec.analyze_password("asd123")
p2 = cybersec.analyze_password("Xk#9pQ!vLm2")
print(f"  asd123: {p1['strength']} (энтропия {p1['entropy_bits']})")
print(f"  Xk#9pQ!vLm2: {p2['strength']} (энтропия {p2['entropy_bits']})")

print("\n=== 6. HASH CHECK ===")
# SHA-256 известного вредоноса — тестирует API MalwareBazaar
h = cybersec.check_hash("d41d8cd98f00b204e9800998ecf8427e")
print(f"  md5 d41d8c...: {h.get('status')}")

print("\n=== 7. EMAIL VALIDATE ===")
v = cybersec.validate_email("test@tempmail.com")
print(f"  tempmail: valid={v['valid']}, disposable={v['disposable']}")
v2 = cybersec.validate_email("test@gmail.com")
print(f"  gmail: valid={v2['valid']}, disposable={v2['disposable']}")

print("\n=== 8. FULL AUDIT ===")
a = cybersec.full_audit("google.com")
print(f"  SSL valid: {a['ssl']['valid']}")
print(f"  Security: {a['site_security'].get('security_grade')}")
print(f"  Email: {a['email_security'].get('grade')}")
print(f"  DNS records: {list(a['dns']['records'].keys())}")
print(f"  WHOIS registar: {a['whois'].get('registrar', '?')}")