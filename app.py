import os
import re
from flask import Flask, render_template, request

app = Flask(__name__)

# Shubhali kalit so'zlar
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'free', 'update', 
    'account', 'pay', 'bonus', 'prize', 'win', 'admin', 
    'karta', 'sms', 'uzcard', 'humo'
]

# Shubhali domenlar
SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.ru']

history_db = []

def analyze_url(url):
    score = 0
    reasons = []
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # IP manzil tekshiruvi
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 40
        reasons.append("IP-manzil ishlatilgan (shubhali domen emas)")

    # Kalit so'zlar
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        score += len(found_keywords) * 15
        reasons.append(f"Shubhali so'zlar topildi: {', '.join(found_keywords)}")

    # Shubhali domen kengaytmasi
    for domain in SUSPICIOUS_DOMAINS:
        if domain in url.lower():
            score += 25
            reasons.append(f"Xavfli domen zonasi: {domain}")

    # Uzunlik tekshiruvi
    if len(url) > 75:
        score += 15
        reasons.append("Havola juda uzun (URL masking bo'lishi mumkin)")

    score = min(score, 100)
    
    if score >= 60:
        status = 'danger'
        title = "🚨 DIQQAT: Yuqori darajadagi fishin xavfi!"
    elif score >= 30:
        status = 'warning'
        title = "⚠️ OGOH BO'LING: Shubhali havola!"
    else:
        status = 'success'
        title = "✅ XAVFSIZ: Shubhali alomatlar topilmadi"

    if not reasons:
        reasons.append("Standart xavfsizlik va format tekshiruvlaridan o'tdi")

    return {
        'percentage': score,
        'status': status,
        'title': title,
        'reasons': reasons
    }

def analyze_text(text):
    score = 0
    reasons = []

    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text.lower()]
    if found_keywords:
        score += len(found_keywords) * 20
        reasons.append(f"Shubhali kalit so'zlar aniqlandi: {', '.join(found_keywords)}")

    if re.search(r'https?://[^\s]+', text):
        score += 30
        reasons.append("Matn ichida tashqi havola bor")

    score = min(score, 100)

    if score >= 60:
        status = 'danger'
        title = "🚨 DIQQAT: Shubhali xabar (Fishin / Firibgarlik)!"
    elif score >= 30:
        status = 'warning'
        title = "⚠️ OGOH BO'LING: Ehtiyotkor bo'ling!"
    else:
        status = 'success'
        title = "✅ XAVFSIZ: Xabarda xavfli belgilar yo'q"

    if not reasons:
        reasons.append("Matnda firibgarlik alomatlari topilmadi")

    return {
        'percentage': score,
        'status': status,
        'title': title,
        'reasons': reasons
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    input_text = ''
    scan_type = 'url'
    
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'url')
        input_text = request.form.get('input_text', '').strip()
        
        if input_text:
            if scan_type == 'url':
                result = analyze_url(input_text)
            else:
                result = analyze_text(input_text)
                
            history_db.insert(0, {
                'type': 'URL' if scan_type == 'url' else 'TEXT',
                'text': input_text,
                'percentage': result['percentage'],
                'status': result['status']
            })
            
    return render_template('index.html', result=result, input_text=input_text, scan_type=scan_type, history=history_db[:5])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
