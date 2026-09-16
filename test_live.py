import asyncio
from datetime import datetime, timezone

import bot as jb
from aiogram.types import Chat, Message, Update, User

OWNER = jb.OWNER


async def send_via(text: str):
    chat = Chat(id=OWNER, type="private")
    user = User(id=OWNER, is_bot=False, first_name="Sender")
    msg = Message(message_id=1, date=datetime.now(timezone.utc), chat=chat, from_user=user, text=text)
    update = Update(update_id=1, message=msg)
    await jb.dp.feed_update(jb.bot, update)
    await asyncio.sleep(2)


async def main():
    jb.dp.include_router(jb.router)
    print("=== LIVE TEST ===")
    await send_via("/ip 8.8.8.8")
    await send_via("/username test")
    await send_via("/pass qwerty123")
    await send_via("/strength Xk#9pQ!vLm2")
    await send_via("/urlcheck http://login-verify-bank.xyz/account/update")
    await send_via("/ssl google.com")
    await send_via("/seccheck https://github.com")
    await send_via("/dmarc google.com")
    await send_via("/validate test@tempmail.com")
    await send_via("/whois github.com")
    await send_via("/dns example.com MX")
    await send_via("/evidence cases")
    await send_via("/watch list")
    await send_via("/report links")
    await send_via("/scan text я знаю твой адрес убью")
    await send_via("/protect ddos")
    await send_via("/protect доксинг")
    await send_via("/protect сватинг")
    await send_via("/netcheck")
    await send_via("/dossier test")
    await send_via("/trace 8.8.8.8")
    await send_via("/authors unknown")
    await send_via("/author gamekirusha")
    await send_via("/gibberish")
    print("=== DONE ===")


if __name__ == "__main__":
    asyncio.run(main())