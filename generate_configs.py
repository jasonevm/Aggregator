
import requests
import re
import os

# 1. ИСТОЧНИКИ (28 ссылок на raw-файлы с конфигами)
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/light.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white.txt"
]
for i in range(1, 21):
    SOURCES.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

# 2. БЕЛЫЙ СПИСОК ДОМЕНОВ (только sni из этого списка пропускаем)
WHITELIST_DOMAINS = [
    'gosuslugi.ru', 'mos.ru', 'nalog.ru', 'kremlin.ru', 'government.ru',
    'sberbank.ru', 'tbank.ru', 'alfabank.ru', 'vtb.ru', 'vk.com', 'ok.ru',
    'mail.ru', 'yandex.ru', 'dzen.ru', 'rutube.ru', 'ozon.ru', 'wildberries.ru',
    'avito.ru', 'rbc.ru', 'tass.ru', '2gis.ru', 'rzd.ru', 'hh.ru'
]

# 3. ФУНКЦИЯ: определяет флаг страны из текста
def extract_flag_and_country(text):
    if '🇺🇸' in text: return {'flag': '🇺🇸', 'country': 'США'}
    if '🇬🇧' in text: return {'flag': '🇬🇧', 'country': 'Великобритания'}
    if '🇩🇪' in text: return {'flag': '🇩🇪', 'country': 'Германия'}
    if '🇫🇷' in text: return {'flag': '🇫🇷', 'country': 'Франция'}
    if '🇫🇮' in text: return {'flag': '🇫🇮', 'country': 'Финляндия'}
    if '🇳🇱' in text: return {'flag': '🇳🇱', 'country': 'Нидерланды'}
    if '🇵🇱' in text: return {'flag': '🇵🇱', 'country': 'Польша'}
    if '🇰🇿' in text: return {'flag': '🇰🇿', 'country': 'Казахстан'}
    return {'flag': '🌐', 'country': 'Anycast'}

# 4. ФУНКЦИЯ: извлекает sni из строки конфига
def extract_sni(url_part, comment):
    sni = ''
    match = re.search(r'[?&]sni=([^&]+)', url_part + '#' + comment)
    if match: 
        sni = requests.utils.unquote(match.group(1))
    return sni or 'sni отсутствует'

# 5. ФУНКЦИЯ: проверяет, есть ли sni в белом списке
def is_whitelisted_sni(sni):
    if not sni: return False
    lower = sni.lower()
    return any(domain in lower or lower.endswith('.' + domain) for domain in WHITELIST_DOMAINS)

# 6. ФУНКЦИЯ: парсит строку, возвращает { url, newName } или null
def parse_config_line(line):
    line = line.strip()
    if not line: return None
    
    parts = line.split('#', 1)
    url_part = parts[0].strip()
    comment = parts[1].strip() if len(parts) > 1 else ''

    if not url_part.startswith('vless://') and not url_part.startswith('vmess://') and not url_part.startswith('trojan://'):
        return None
    
    flag_country = extract_flag_and_country(comment + ' ' + url_part)
    sni = extract_sni(url_part, comment)
    
    if not is_whitelisted_sni(sni):
        return None
                          
    return {'url': url_part, 'newName': f"{flag_country['flag']} {flag_country['country']} | sni = {sni} | от катлер"}

# 7. ФУНКЦИЯ: скачивает и парсит один источник
def fetch_source(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return [
            parse_config_line(line)
            for line in response.text.split('\n')
        ]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return []

# 8. ГЛАВНАЯ ФУНКЦИЯ: сбор, фильтрация, сохранение
def main():
    LIMIT = 500 # Default limit, can be made configurable if needed
    
    all_configs = []
    url_set = set()
    
    for url in SOURCES:
        if len(all_configs) >= LIMIT: break
        configs = fetch_source(url)
        for cfg in configs:
            if cfg and cfg['url'] not in url_set:
                url_set.add(cfg['url'])
                all_configs.append(cfg)
                if len(all_configs) >= LIMIT: break

    # In a GitHub Action, we don't have Google Drive for versioning. 
    # We'll just generate the file and let Git handle the version history.
    # For a simple version, we can use a timestamp or a simple counter if needed.
    # For now, let's omit the explicit version number in the header for simplicity
    # or use a fixed one.
    
    # The original script uses a version from Google Drive. 
    # For GitHub Actions, we can use the run ID or a simple incrementing number 
    # stored in the repo itself, or just a date.
    # Let's use a simple date for now, or a placeholder.
    
    # Placeholder for version. In a real GitHub Action, you might pass the run ID or a date.
    # For now, let's use a fixed placeholder or generate a simple date.
    import datetime
    current_version = datetime.datetime.now().strftime("%Y%m%d.%H%M")

    header = [
        "#profile-title: WhiteJ",
        "#profile-update-interval: 2",
        f"#announce: ⚡️ WhiteJ version: {1} ⚡️",
        "#profile-web-page-url: https://github.com/jasonevm/whitej",
        ""
    ]
    
    content = '\n'.join(header)
    for cfg in all_configs:
        content += f"\n{cfg['url']}#{cfg['newName']}"
    
    # Print to stdout, which will be captured by the GitHub Action and saved to a file
    print(content)

if __name__ == '__main__':
    main()
