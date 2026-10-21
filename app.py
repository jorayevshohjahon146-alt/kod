import os
import re
from flask import Flask, render_template, request

app = Flask(__name__)

# Kengaytirilgan tahdidlar bazasi
SUSPICIOUS_KEYWORDS = [
    'login',
    'verify',
    'bank',
    'secure',
    'free',
    'update',
    'account',
    'pay',
    'bonus',
    'prize',
    'win',
    'admin',
    'karta',
    'sms',
    'uzcard',
    'humo',
    'bonus',
]
SUSPICIOUS_DOMAINS = [
    '.tk',
    '.ml',
    '.ga',
    '.cf',
    '.gq',
    'free-xyz',
    '000webhost',
    'temp-link',
    'xyz',
    'sec-verify',
    'update-app',
]
DANGEROUS_EXTENSIONS = ['.apk', '.exe', '.bat', '.scr', '.pif', '.zip', '.rar']
CARD_THEFT_PHRASES = [
    "karta raqamini kiriting",
    'balansni tekshirish',
    'pulni yechib olish',
    'cvv',
    'pin-kod',
    'sms kodni yozing',
    '16 xonali',
]

scan_history = []


@app.route('/', methods=['GET', 'POST'])
def home():
  result = None
  input_text = ''
  scan_type = 'url'

  if request.method == 'POST':
    scan_type = request.form.get('scan_type', 'url')
    input_text = request.form.get('input_text', '').strip()

    if input_text:
      score = 0
      max_score = 15  # Maksimal xavf ballioshirildi
      reasons = []

      text_lower = input_text.lower()

      if scan_type == 'url':
        # 1. Fayl kengaytmalarini tekshirish (.apk va h.k.)
        for ext in DANGEROUS_EXTENSIONS:
          if ext in text_lower:
            score += 6
            reasons.append(
                '🚨 Kritik tahdid: Havolada zararli dastur yoki fayl formati'
                f" aniqlandi ('{ext}')."
            )

        # 2. HTTPS protokoli mavjudligi
        if not text_lower.startswith('https://'):
          score += 3
          reasons.append(
              '⚠️ Xavfsiz emas: HTTPS shifrlangan protokoli ishlatilmagan'
              ' (HTTP).'
          )

        # 3. Shubhali kalit so'zlar
        kw_count = sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in text_lower
        )
        if kw_count > 0:
          score += kw_count * 2
          reasons.append(
              f'🔍 Phishing belgisi: URL tarkibida {kw_count} ta shubhali so\'z'
              ' topildi.'
          )

        # 4. Shubhali domenlar
        for domain in SUSPICIOUS_DOMAINS:
          if domain in text_lower:
            score += 5
            reasons.append(
                f"🛑 Xavfli zona: '{domain}' domeni firibgarlar bazasiga mos"
                ' keladi.'
            )
      else:
        # Matn va SMS tahlili (Karta o'g'riligi va ijtimoiy muhandislik)
        phishing_phrases = [
            'parolni yangilang',
            'yutib oldingiz',
            'kartani kiriting',
            'shoshilinch',
            'blocked',
            'account suspended',
            'login to confirm',
            'apk yuklab oling',
            'sms kodni yuboring',
        ]
        found_phrases = [p for p in phishing_phrases if p in text_lower]

        if found_phrases:
          score += len(found_phrases) * 3
          reasons.append(
              f"⚠️ Ijtimoiy muhandislik: '{', '.join(found_phrases)}'"
              ' psixologik bosim elementlari.'
          )

        # Karta o'g'riligi xavfi
        card_threats = [c for c in CARD_THEFT_PHRASES if c in text_lower]
        if card_threats:
          score += 6
          reasons.append(
              '💳 Karta xavfi: Maxfiy to‘lov ma\'lumotlarini so‘rovchi iboralar'
              f" topildi ({', '.join(card_threats)})."
          )

      # Ballni chegaralash va foizga o'tkazish
      score = min(score, max_score)
      risk_percentage = int((score / max_score) * 100)

      # Natija holati
      if risk_percentage >= 60:
        result = {
            'status': 'danger',
            'title': '🛑 Yuqori Xavf (Malicious / Phishing)',
            'percentage': risk_percentage,
            'reasons': reasons,
        }
      elif risk_percentage >= 25:
        result = {
            'status': 'warning',
            'title': '⚡ Shubhali (Suspicious)',
            'percentage': risk_percentage,
            'reasons': reasons,
        }
      else:
        result = {
            'status': 'safe',
            'title': '✅ Xavfsiz (Clean / Verified)',
            'percentage': risk_percentage,
            'reasons': [
                'Hech qanday tahdid yoki shubhali kod/havola topilmadi.'
                ' Xavfsiz foydalanishingiz mumkin.'
            ],
        }

      # Tarixga qo'shish (Oxirgi 6 tasi)
      scan_history.insert(
          0,
          {
              'type': scan_type.upper(),
              'text': input_text,
              'status': result['status'],
              'title': result['title'],
              'percentage': risk_percentage,
          },
      )
      if len(scan_history) > 6:
        scan_history.pop()

  return render_template(
      'index.html',
      result=result,
      input_text=input_text,
      scan_type=scan_type,
      history=scan_history,
  )


if __name__ == '__main__':
  # Render uchun PORT va host sozlamasi
  port = int(os.environ.get('PORT', 5000))
  app.run(host='0.0.0.0', port=port)
    
