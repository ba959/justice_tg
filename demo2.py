import sys, os
sys.path.insert(0, os.getcwd())
import evidence
from datetime import datetime, timezone

print("=== ДОКАЗАТЕЛЬСТВО С SHA-256 ХЕШЕМ ===")

class FakeMsg:
    def __init__(self, author, content):
        self.author = author
        self.content = content
        self.created_at = datetime.now(timezone.utc)

msgs = [
    FakeMsg("BadDoker", "я знаю твой адрес 123 ул."),
    FakeMsg("BadDoker", "сваты приедут завтра"),
    FakeMsg("User", "не сметь!"),
]
rec = evidence.snapshot_user("BadDoker", 99999, msgs)
print(f"Кейс:    {rec['case']}")
print(f"SHA-256: {rec['sha256']}")
print(f"Время:   {rec['saved_at']}")

v = evidence.verify_case(rec["case"])
print(f"Проверка: {v['ok']}")

print("\nТекст доказательства:")
with open(os.path.join(evidence.config.EVIDENCE_DIR, rec["case"], "evidence.txt")) as f:
    for i, line in enumerate(f):
        print(f"  {i+1}: {line.rstrip()}")

evidence.save_case("test_case_123", {"target_name": "угроза", "messages": 1},
    "Было написано: мой адрес 123, приедут и все")
c2 = evidence.verify_case("test_case_123")
print(f"\ncase test_case_123: sha256={c2['ok']}")
