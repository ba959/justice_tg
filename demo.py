import osint
import evidence
import os, sys

d = osint.lookup_ip("8.8.8.8")
print("=== IP 8.8.8.8 ===")
print(f"  Страна: {d.get('country')}")
print(f"  Город: {d.get('city')}")
print(f"  Провайдер: {d.get('isp')}")
print(f"  Координаты: {d.get('lat')}, {d.get('lon')}")

print("\n=== Ник 'test' на платформах ===")
for name, st, url in osint.check_username("test"):
    mark = "YES" if st == "НАЙДЕН" else "NO" if st == "Свободен" else "?"
    print(f"  {mark} {name}")

print("\n=== Пароль 'qwerty123' ===")
p = osint.password_breached("qwerty123")
print(f"  В утечках: {p.get('count', 0)} раз")

print("\n=== Пароль 'sTr0ng!P4ss' ===")
p2 = osint.password_breached("sTr0ng!P4ss")
print(f"  В утечках: {'Да (' + str(p2.get('count','?')) + ')' if p2['pwned'] else 'Нет'}")

print("\n=== Домен github.com ===")
r = osint.domain_info("github.com")
print(f"  Регистратор: {r.get('registrar')}")
print(f"  Создан: {r.get('created')}")

print("\n=== DNS example.com TXT ===")
dns = osint.dns_lookup("example.com", "TXT")
for a in dns[:3]:
    print(f"  {a.get('data','')}")

print("\n=== Снимок https://example.com ===")
s = osint.site_snapshot("https://example.com")
print(f"  Статус: {s.get('status')}")
print(f"  Заголовок: {s.get('title')}")
print(f"  SHA-256: {s.get('sha256','')[:32]}...")

print("\n=== Поиск угроз ===")
t1 = osint.threat_words_in("я знаю твой адрес, сват позови")
t2 = osint.threat_words_in("привет как дела")
print(f"  'я знаю твой адрес...': {t1}")
print(f"  'привет как дела': {t2}")

print("\n=== Evidence (доказательство с хешем) ===")
rec = evidence.snapshot_user("TestUser", 12345, [type('M',(),{'content':'тест сообщение','created_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc)})()])
print(f"  Кейс: {rec['case']}")
print(f"  SHA-256: {rec['sha256']}")
print(f"  Проверка целостности: {evidence.verify_case(rec['case'])['ok']}")
