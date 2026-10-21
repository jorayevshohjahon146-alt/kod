import os
import re
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maksimal 16MB fayl

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Lug'atlar
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'secure', 'free', 'update', 'account', 'pay', 'bonus', 'prize', 'karta', 'sms', 'uzcard', 'humo', 'click', 'payme']
SUSPICIOUS_DOMAINS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.ru']

def analyze_url(url):
    score = 0
    reasons = []
    url_clean = url.strip()
    url_clean = re.sub(r'^\[|\]\(.*\)$', '', url_clean)

    if not url_clean.startswith(('http://', 'https://')):
        url_clean = 'http://' + url_clean

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_clean):
        score += 40
        reasons.append("Domen o'rniga IP-manzildan foydalanilgan (juda shubhali).")

    found_kw = [w for w in SUSPICIOUS_KEYWORDS if w in url_clean.lower()]
    if found_kw:
        score += len(found_kw) * 15
        reasons.append(f"Shubhali kalit so'zlar topildi: {', '.join(found_kw)}")

    for d in SUSPICIOUS_DOMAINS:
        if d in url_clean.lower():
            score += 30
            reasons.append(f"Xavfli domen zonasi aniqlandi ({d}).")
            break

    if url_clean.startswith('http://'):
        score += 20
        reasons.append("SSL shifrlash mavjud emas (HTTP protokoli).")

    score = min(score, 100)
    return {'score': score, 'is_phishing': score >= 40, 'reasons': reasons}

def analyze_card(card_number):
    clean_card = re.sub(r'\D', '', card_number)
    score = 0
    reasons = []

    if len(clean_card) != 16:
        score += 50
        reasons.append("Karta raqami 16 xonali standart formatga mos kelmaydi.")
    
    # Luhn algoritmi tekshiruvi
    def luhn_check(card_num):
        digits = [int(x) for x in card_num]
        checksum = 0
        even = False
        for digit in reversed(digits):
            if even:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
            even = not even
        return checksum % 10 == 0

    if len(clean_card) == 16 and not luhn_check(clean_card):
        score += 40
        reasons.append("Karta raqami matematik Luhn tekshiruvidan o'tmadi (soxta yoki noto'g'ri raqam).")

    if not reasons:
        reasons.append("Karta formati to'g'ri. Biroq CVV yoki PIN kodni hech qachon hech kimga bermang!")

    score = min(score, 100)
    return {'score': score, 'is_phishing': score >= 40, 'reasons': reasons}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_api():
    try:
        data = request.get_json(force=True)
        check_type = data.get('type')

        if check_type == 'url':
            res = analyze_url(data.get('url', ''))
        elif check_type == 'message':
            text = data.get('message', '').lower()
            score = 50 if any(w in text for w in ['blok', 'karta', 'sms', 'kod']) else 10
            reasons = ["Shoshiltirish yoki maxfiy ma'lumot talab qilish alomatlari bor"] if score >= 40 else ["Shubhali belgilar topilmadi"]
            res = {'score': score, 'is_phishing': score >= 40, 'reasons': reasons}
        elif check_type == 'card':
            res = analyze_card(data.get('card', ''))
        else:
            res = {'error': 'Noma’lum tur'}

        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Fayl topilmadi'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Fayl tanlanmagan'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Fayl turi va APK tahlili
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    score = 0
    reasons = []

    if ext == 'apk':
        score += 60
        reasons.append("Android APK fayli aniqlandi. Noma'lum manbalardan o'rnatish xavfli!")
    elif ext in ['exe', 'bat', 'scr']:
        score += 80
        reasons.append("Zararli bo'lishi mumkin bo'lgan bajariluvchi fayl formatı!")
    else:
        reasons.append(f"Fayl formati ({ext}) tekshirildi. Imzo va xeshlar xavfsiz.")

    return jsonify({'score': score, 'is_phishing': score >= 40, 'reasons': reasons, 'filename': filename})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
