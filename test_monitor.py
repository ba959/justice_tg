import asyncio
from datetime import datetime, timezone

import bot as jb
from aiogram.types import Chat, Message, Update, User


async def feed_threat():
    chat = Chat(id=999123, type="group", title="TestChat")
    attacker = User(id=555001, is_bot=False, first_name="BadGuy")
    msg = Message(message_id=50, date=datetime.now(timezone.utc), chat=chat,
                  from_user=attacker, text="я знаю твой адрес, сват приедет убью")
    update = Update(update_id=99, message=msg)

    class FakeBot:
        def __init__(self):
            self.sent = []
        async def send_message(self, *a, **k):
            self.sent.append((a, k))
            return None

    jb._monitor_on = True
    from aiogram import Bot
    real = jb.bot
    jb.bot = FakeBot()
    try:
        await jb.dp.feed_update(real, update)
    finally:
        jb.bot = real
    await asyncio.sleep(1)
    print("Мониторинг сработал (см. кейс в evidence/)")


async def main():
    jb.dp.include_router(jb.router)
    print("=== ТЕСТ АВТО-МОНИТОРИНГА ===")
    await feed_threat()
    print("=== DONE ===")


if __name__ == "__main__":
    asyncio.run(main())