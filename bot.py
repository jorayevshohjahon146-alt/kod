import logging
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

TOKEN = '8824986874:AAHXOsLmb8tAq3A6_S0M0FdpoockRuvrzcg'

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'secure', 'free', 'update', 'account', 'pay', 'bonus', 'prize', 'win', 'admin', 'karta', 'sms', 'uzcard', 'humo']
SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.gq', 'free-xyz', '000webhost', 'temp-link', 'xyz', 'sec-verify']
DANGEROUS_EXTENSIONS = ['.apk', '.exe', '.bat', '.scr', '.pif', '.zip', '.rar']
CARD_THEFT_PHRASES = ['karta raqamini kiriting', 'balans', 'cvv', 'pin-kod', 'sms kod', '16 xonali']

def analyze_input(input_text):
    score = 0
    max_score = 15
    reasons = []
    text_lower = input_text.lower()

    # Zararli fayl / APK
    for ext in DANGEROUS_EXTENSIONS:
        if ext in text_lower:
            score += 6
            reasons.append(f"🚨 **Zararli fayl:** `{ext}` formati aniqlandi.")

    # URL / Protokol
    if 'http://' in text_lower:
        score += 3
        reasons.append("⚠️ **Shubhali protokol:** HTTPS emas, HTTP ishlatilmoqda.")

    # Kalit so'zlar
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower)
    if kw_count > 0:
        score += kw_count * 2
        reasons.append(f"🔍 **Phishing belgilari:** {kw_count} ta shubhali so'z topildi.")

    # Domenlar
    for domain in SUSPICIOUS_DOMAINS:
        if domain in text_lower:
            score += 5
            reasons.append(f"🛑 **Xavfli domen:** `{domain}` zone aniqlandi.")

    # Karta o'g'riligi
    for cp in CARD_THEFT_PHRASES:
        if cp in text_lower:
            score += 5
            reasons.append(f"💳 **Karta xavfi:** Maxfiy ma'lumotlarni so'rovchi ibora topildi ('{cp}').")

    score = min(score, max_score)
    risk_percentage = int((score / max_score) * 100)
    return risk_percentage, reasons

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ **PhishGuard Pro AI Botiga xush kelibsiz!**\n\n"
        "Menga istalgan:\n"
        "🔗 **URL Havolani**\n"
        "📱 **.APK fayl havolasini**\n"
        "💳 **Shubhali SMS yoki Matnni** yuboring.\n\n"
        "Men uni darhol kiberxavfsizlik va firibgarlikka tekshirib beraman!"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    risk_percentage, reasons = analyze_input(user_text)

    if risk_percentage >= 60:
        status_icon = "🛑"
        status_title = "YUQORI XAVF (MALICIOUS)"
    elif risk_percentage >= 25:
        status_icon = "⚡"
        status_title = "SHUBHALI (SUSPICIOUS)"
    else:
        status_icon = "✅"
        status_title = "XAVFSIZ (CLEAN)"

    response = f"{status_icon} **Tahlil Natijasi: {status_title}**\n"
    response += f"📊 **Xavf darajasi:** {risk_percentage}%\n\n"

    if reasons:
        response += "📋 **Aniqlangan tahdidlar:**\n"
        for r in reasons:
            response += f"• {r}\n"
    else:
        response += "✅ Hech qanday tahdid topilmadi. Xavfsiz."

    await update.message.reply_text(response, parse_mode="Markdown")

if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 PhishGuard Pro Telegram Boti mukammal rejimda ishga tushdi...")
    app.run_polling()