import re
import whois
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import socket

PHISH_HINTS = ['secure', 'account', 'update', 'login', 'signin', 'verify', 
               'banking', 'confirm', 'password', 'credential', 'paypal', 
               'apple', 'amazon', 'microsoft', 'support']

SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 
                       'shorte.st', 'is.gd', 'buff.ly', 'adf.ly']

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.site', '.tk', 
                   '.ml', '.ga', '.cf', '.gq', '.pw']

KNOWN_BRANDS = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook',
                'instagram', 'twitter', 'netflix', 'ebay', 'chase', 'wellsfargo',
                'bankofamerica', 'dhl', 'fedex', 'ups']

def get_page_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=5, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        return response, soup
    except:
        return None, None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except:
        return None

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    hostname = domain.split(':')[0]  # strip port if present

    response, soup = get_page_content(url)
    w = get_whois_info(domain)

    features = {}

    # --- URL BASED FEATURES ---

    # 1. length_url
    features['length_url'] = len(url)

    # 2. length_hostname
    features['length_hostname'] = len(hostname)

    # 3. ip — is hostname an IP address?
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    features['ip'] = 1 if ip_pattern.match(hostname) else 0

    # 4. nb_dots
    features['nb_dots'] = url.count('.')

    # 5. nb_hyphens
    features['nb_hyphens'] = url.count('-')

    # 6. nb_at
    features['nb_at'] = url.count('@')

    # 7. nb_qm
    features['nb_qm'] = url.count('?')

    # 8. nb_and
    features['nb_and'] = url.count('&')

    # 9. nb_or
    features['nb_or'] = url.count('|')

    # 10. nb_eq
    features['nb_eq'] = url.count('=')

    # 11. nb_underscore
    features['nb_underscore'] = url.count('_')

    # 12. nb_tilde
    features['nb_tilde'] = url.count('~')

    # 13. nb_percent
    features['nb_percent'] = url.count('%')

    # 14. nb_slash
    features['nb_slash'] = url.count('/')

    # 15. nb_star
    features['nb_star'] = url.count('*')

    # 16. nb_colon
    features['nb_colon'] = url.count(':')

    # 17. nb_comma
    features['nb_comma'] = url.count(',')

    # 18. nb_semicolumn
    features['nb_semicolumn'] = url.count(';')

    # 19. nb_dollar
    features['nb_dollar'] = url.count('$')

    # 20. nb_space
    features['nb_space'] = url.count(' ') + url.count('%20')

    # 21. nb_www
    features['nb_www'] = url.lower().count('www')

    # 22. nb_com
    features['nb_com'] = url.lower().count('.com')

    # 23. nb_dslash
    features['nb_dslash'] = url.count('//')

    # 24. http_in_path
    features['http_in_path'] = 1 if 'http' in path else 0

    # 25. https_token
    features['https_token'] = 1 if 'https' in domain else 0

    # 26. ratio_digits_url
    digits_url = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = round(digits_url / len(url), 4) if url else 0

    # 27. ratio_digits_host
    digits_host = sum(c.isdigit() for c in hostname)
    features['ratio_digits_host'] = round(digits_host / len(hostname), 4) if hostname else 0

    # 28. punycode — internationalized domain
    features['punycode'] = 1 if 'xn--' in hostname else 0

    # 29. port — non standard port used?
    try:
        port = parsed.port
        features['port'] = 1 if port and port not in [80, 443] else 0
    except:
        features['port'] = 0

    # 30. tld_in_path
    common_tlds = ['.com', '.org', '.net', '.gov', '.edu']
    features['tld_in_path'] = 1 if any(t in path for t in common_tlds) else 0

    # 31. tld_in_subdomain
    subdomain = '.'.join(hostname.split('.')[:-2]) if hostname.count('.') >= 2 else ''
    features['tld_in_subdomain'] = 1 if any(t in subdomain for t in common_tlds) else 0

    # 32. abnormal_subdomain
    features['abnormal_subdomain'] = 1 if re.search(r'(^|\.)(w+\d+|mail\d+|secure\d+)', hostname) else 0

    # 33. nb_subdomains
    features['nb_subdomains'] = len(hostname.split('.')) - 2 if hostname.count('.') >= 2 else 0

    # 34. prefix_suffix — hyphen in domain
    features['prefix_suffix'] = 1 if '-' in hostname else 0

    # 35. random_domain — high consonant ratio suggests random string
    vowels = sum(1 for c in hostname if c in 'aeiou')
    consonants = sum(1 for c in hostname if c.isalpha() and c not in 'aeiou')
    ratio = consonants / (vowels + 1)
    features['random_domain'] = 1 if ratio > 4 else 0

    # 36. shortening_service
    features['shortening_service'] = 1 if any(s in url for s in SHORTENING_SERVICES) else 0

    # 37. path_extension — suspicious file extensions
    suspicious_ext = ['.php', '.asp', '.exe', '.dll', '.cgi']
    features['path_extension'] = 1 if any(ext in path for ext in suspicious_ext) else 0

    # --- REDIRECTION FEATURES ---

    # 38. nb_redirection
    try:
        features['nb_redirection'] = len(response.history) if response else 0
    except:
        features['nb_redirection'] = 0

    # 39. nb_external_redirection
    try:
        ext_redirects = sum(1 for r in response.history if domain not in r.url) if response else 0
        features['nb_external_redirection'] = ext_redirects
    except:
        features['nb_external_redirection'] = 0

    # --- WORD BASED FEATURES ---

    words_raw = re.split(r'\W+', url)
    words_raw = [w for w in words_raw if w]
    word_lengths = [len(w) for w in words_raw] if words_raw else [0]

    host_words = re.split(r'\W+', hostname)
    host_words = [w for w in host_words if w]
    host_lengths = [len(w) for w in host_words] if host_words else [0]

    path_words = re.split(r'\W+', path)
    path_words = [w for w in path_words if w]
    path_lengths = [len(w) for w in path_words] if path_words else [0]

    # 40. length_words_raw
    features['length_words_raw'] = len(words_raw)

    # 41. char_repeat — max repeated character sequence
    max_repeat = max((len(m.group(0)) for m in re.finditer(r'(.)\1+', url)), default=0)
    features['char_repeat'] = max_repeat

    # 42-44. shortest words
    features['shortest_words_raw'] = min(word_lengths)
    features['shortest_word_host'] = min(host_lengths)
    features['shortest_word_path'] = min(path_lengths)

    # 45-47. longest words
    features['longest_words_raw'] = max(word_lengths)
    features['longest_word_host'] = max(host_lengths)
    features['longest_word_path'] = max(path_lengths)

    # 48-50. average word lengths
    features['avg_words_raw'] = round(sum(word_lengths) / len(word_lengths), 2)
    features['avg_word_host'] = round(sum(host_lengths) / len(host_lengths), 2)
    features['avg_word_path'] = round(sum(path_lengths) / len(path_lengths), 2)

    # 51. phish_hints — phishing keywords in URL
    features['phish_hints'] = sum(1 for hint in PHISH_HINTS if hint in url.lower())

    # 52. domain_in_brand
    features['domain_in_brand'] = 1 if any(brand in hostname for brand in KNOWN_BRANDS) else 0

    # 53. brand_in_subdomain
    features['brand_in_subdomain'] = 1 if any(brand in subdomain for brand in KNOWN_BRANDS) else 0

    # 54. brand_in_path
    features['brand_in_path'] = 1 if any(brand in path for brand in KNOWN_BRANDS) else 0

    # 55. suspicious_tld
    features['suspecious_tld'] = 1 if any(url.lower().endswith(tld) or tld + '/' in url.lower() for tld in SUSPICIOUS_TLDS) else 0

    

    # --- PAGE CONTENT FEATURES ---

    # 57. nb_hyperlinks
    try:
        links = soup.find_all('a', href=True) if soup else []
        features['nb_hyperlinks'] = len(links)
    except:
        features['nb_hyperlinks'] = 0

    # 58-60. hyperlink ratios
    try:
        int_links = sum(1 for l in links if domain in l['href'])
        ext_links = sum(1 for l in links if domain not in l['href'] and l['href'].startswith('http'))
        null_links = sum(1 for l in links if l['href'] in ['#', 'javascript:void(0)', ''])
        total = len(links) if links else 1
        features['ratio_intHyperlinks'] = round(int_links / total, 4)
        features['ratio_extHyperlinks'] = round(ext_links / total, 4)
        features['ratio_nullHyperlinks'] = round(null_links / total, 4)
    except:
        features['ratio_intHyperlinks'] = 0
        features['ratio_extHyperlinks'] = 0
        features['ratio_nullHyperlinks'] = 0

    # 61. nb_extCSS
    try:
        css_links = soup.find_all('link', rel='stylesheet') if soup else []
        ext_css = sum(1 for c in css_links if 'href' in c.attrs and domain not in c['href'])
        features['nb_extCSS'] = ext_css
    except:
        features['nb_extCSS'] = 0

    # 62-63. redirection ratios in page
    features['ratio_intRedirection'] = 0
    features['ratio_extRedirection'] = 0

    # 64-65. error ratios
    features['ratio_intErrors'] = 0
    features['ratio_extErrors'] = 0

    # 66. login_form
    try:
        forms = soup.find_all('form') if soup else []
        has_login = any(
            'login' in str(f).lower() or 
            'password' in str(f).lower() or 
            'signin' in str(f).lower() 
            for f in forms
        )
        features['login_form'] = 1 if has_login else 0
    except:
        features['login_form'] = 0

    # 67. external_favicon
    try:
        icon = soup.find('link', rel=lambda x: x and 'icon' in x) if soup else None
        if icon and 'href' in icon.attrs:
            features['external_favicon'] = 1 if domain not in icon['href'] else 0
        else:
            features['external_favicon'] = 0
    except:
        features['external_favicon'] = 0

    # 68. links_in_tags
    try:
        script_links = soup.find_all('script', src=True) if soup else []
        ext_scripts = sum(1 for s in script_links if domain not in s['src'])
        features['links_in_tags'] = ext_scripts
    except:
        features['links_in_tags'] = 0

    # 69. submit_email
    try:
        features['submit_email'] = 1 if 'mailto:' in (response.text if response else '') else 0
    except:
        features['submit_email'] = 0

    # 70-71. media ratios
    features['ratio_intMedia'] = 0
    features['ratio_extMedia'] = 0

    # 72. sfh — server form handler suspicious
    try:
        forms = soup.find_all('form', action=True) if soup else []
        sfh_suspicious = any(
            f['action'] in ['', '#', 'about:blank'] or 
            (f['action'].startswith('http') and domain not in f['action'])
            for f in forms
        )
        features['sfh'] = 1 if sfh_suspicious else 0
    except:
        features['sfh'] = 0

    # 73. iframe
    try:
        features['iframe'] = 1 if soup and soup.find('iframe') else 0
    except:
        features['iframe'] = 0

    # 74. popup_window
    try:
        features['popup_window'] = 1 if response and 'window.open' in response.text.lower() else 0
    except:
        features['popup_window'] = 0

    # 75. safe_anchor
    try:
        unsafe = sum(1 for l in links if l['href'] in ['#', 'javascript:void(0)'])
        features['safe_anchor'] = round(unsafe / len(links), 4) if links else 0
    except:
        features['safe_anchor'] = 0

    # 76. onmouseover
    try:
        features['onmouseover'] = 1 if response and 'onmouseover' in response.text.lower() else 0
    except:
        features['onmouseover'] = 0

    # 77. right_clic
    try:
        features['right_clic'] = 1 if response and 'contextmenu' in response.text.lower() else 0
    except:
        features['right_clic'] = 0

    # 78. empty_title
    try:
        title = soup.find('title') if soup else None
        features['empty_title'] = 1 if not title or not title.text.strip() else 0
    except:
        features['empty_title'] = 0

    # 79. domain_in_title
    try:
        title_text = soup.find('title').text.lower() if soup and soup.find('title') else ''
        features['domain_in_title'] = 1 if hostname.split('.')[0] in title_text else 0
    except:
        features['domain_in_title'] = 0

    # 80. domain_with_copyright
    try:
        page_text = soup.get_text().lower() if soup else ''
        features['domain_with_copyright'] = 1 if hostname.split('.')[0] in page_text and '©' in page_text else 0
    except:
        features['domain_with_copyright'] = 0

    # --- WHOIS FEATURES ---

    # 81. whois_registered_domain
    try:
        features['whois_registered_domain'] = 1 if w and w.domain_name else 0
    except:
        features['whois_registered_domain'] = 0

    # 82. domain_registration_length
    try:
        exp = w.expiration_date
        creation = w.creation_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(creation, list): creation = creation[0]
        if exp and creation:
            if exp.tzinfo is not None and creation.tzinfo is not None:
                features['domain_registration_length'] = (exp - creation).days
            elif exp.tzinfo is None and creation.tzinfo is None:
                features['domain_registration_length'] = (exp - creation).days
            else:
                from datetime import timezone
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                features['domain_registration_length'] = (exp - creation).days
        else:
            features['domain_registration_length'] = 0
    except:
        features['domain_registration_length'] = 0

    # 83. domain_age
    try:
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            if creation.tzinfo is not None:
                from datetime import timezone
                now = datetime.now(timezone.utc)
            else:
                now = datetime.now()
            features['domain_age'] = (now - creation).days
        else:
            features['domain_age'] = 0
    except:
        features['domain_age'] = 0

    # 84. dns_record
    try:
        socket.gethostbyname(hostname)
        features['dns_record'] = 1
    except:
        features['dns_record'] = 0

    return list(features.values())