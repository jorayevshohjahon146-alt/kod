import re
import json
import threading
import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# --- BOTNI ORQA FONDA ISHGA TUSHIRISH (To'g'ri joyi) ---
def run_bot():
    try:
        os.system("python bot.py")
    except Exception as e:
        print("Bot error:", e)

# Render va Gunicorn uchun mos ravishda orqa fonda ishga tushirish
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    threading.Thread(target=run_bot, daemon=True).start()
# ------------------------------------------------------

# PhishGuard Pro AI - Tahdidlarni aniqlash lug'atlari
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'free', 'update',
    'account', 'pay', 'bonus', 'prize', 'win', 'admin',
    'karta', 'sms', 'uzcard', 'humo', 'click', 'payme'
]
SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.ru']

def analyze_url(url):
    score = 0
    reasons = []
    url_clean = url.strip()
    url_clean = re.sub(r'^\[|\]\(.*\)$', '', url_clean)
    url_clean = re.sub(r'[\[\]\(\)]', '', url_clean)

    if not url_clean.startswith(('http://', 'https://')):
        url_clean = 'http://' + url_clean

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_clean):
        score += 35
        reasons.append("Domen o'rniga IP-manzildan foydalanilgan (juda shubhali).")

    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url_clean.lower()]
    if found_keywords:
        score += len(found_keywords) * 15
        reasons.append(f"Shubhali kalit so'zlar aniqlandi: {', '.join(found_keywords)}")

    for domain in SUSPICIOUS_DOMAINS:
        if domain in url_clean.lower():
            score += 25
            reasons.append(f"Xavfli/bepul domen zonasidan foydalanilgan ({domain}).")
            break

    if url_clean.startswith('http://'):
        score += 15
        reasons.append("Sayt xavfsiz HTTPS protokolidan foydalanmaydi (HTTP).")

    if len(url_clean) > 60:
        score += 10
        reasons.append("URL manzil o'ta uzun (phishing havolalariga xos).")

    if '@' in url_clean:
        score += 30
        reasons.append("URL tarkibida shubhali '@' belgisi mavjud.")

    score = min(score, 100)
    return {'url': url_clean, 'score': score, 'is_phishing': score >= 40, 'reasons': reasons}

def analyze_message(text):
    score = 0
    reasons = []
    text_lower = text.lower()
    
    urgent_words = ['tezda', 'shoshiling', 'bloklanadi', 'yopiladi', '24 soat', 'xavf']
    sensitive_words = ['sms', 'kod', 'karta', 'pasport', 'parol', 'pin']
    
    found_urgent = [w for w in urgent_words if w in text_lower]
    found_sensitive = [w for w in sensitive_words if w in text_lower]

    if found_urgent:
        score += 40
        reasons.append(f"Shoshiltirish va qo'rqitish belgilari: {', '.join(found_urgent)}")
    if found_sensitive:
        score += 45
        reasons.append(f"Maxfiy ma'lumotlar so'rash belgisi: {', '.join(found_sensitive)}")
        
    score = min(score, 100)
    return {'score': score, 'is_phishing': score >= 40, 'reasons': reasons}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_api():
    try:
        data = request.get_json(force=True)
        check_type = data.get('type', 'url')
        
        if check_type == 'message':
            msg = data.get('message', '')
            res = analyze_message(msg)
        else:
            url = data.get('url', '')
            res = analyze_url(url)
            
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
