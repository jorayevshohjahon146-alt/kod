import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'free', 'update',
    'account', 'pay', 'bonus', 'prize', 'win', 'admin',
    'karta', 'sms', 'uzcard', 'humo'
]

SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.ru']

def analyze_url(url):
    score = 0
    reasons = []

    url_clean = url.strip()
    
    # URL formatini tozalash (Markdown yoki qavslar bo'lsa)
    url_clean = re.sub(r'^\[|\]\(.*\)$', '', url_clean)
    url_clean = re.sub(r'[\[\]\(\)]', '', url_clean)

    if not url_clean.startswith(('http://', 'https://')):
        url_clean = 'http://' + url_clean

    # 1. IP manzil tekshiruvi
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_clean):
        score += 35
        reasons.append("Domen o'rniga IP-manzildan foydalanilgan (juda shubhali).")

    # 2. Kalit so'zlar tekshiruvi
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url_clean.lower()]
    if found_keywords:
        score += len(found_keywords) * 15
        reasons.append(f"Shubhali kalit so'zlar aniqlandi: {', '.join(found_keywords)}")

    # 3. Shubhali domen kengaytmasi
    for domain in SUSPICIOUS_DOMAINS:
        if domain in url_clean.lower():
            score += 25
            reasons.append(f"Xavfli/bepul domen zonasidan foydalanilgan ({domain}).")
            break

    # 4. HTTPS yo'qligi
    if url_clean.startswith('http://'):
        score += 15
        reasons.append("Sayt xavfsiz HTTPS protokolidan foydalanmaydi (HTTP).")

    # 5. Belgilar uzunligi va '@' belgisi
    if len(url_clean) > 60:
        score += 10
        reasons.append("URL manzil o'ta uzun (phishing havolalariga xos).")

    if '@' in url_clean:
        score += 30
        reasons.append("URL tarkibida shubhali '@' belgisi mavjud.")

    score = min(score, 100)
    is_phishing = score >= 40

    return {
        'url': url_clean,
        'score': score,
        'is_phishing': is_phishing,
        'reasons': reasons
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_api():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'URL kiritilmadi'}), 400
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
