import json
import re
from pathlib import Path
from urllib.parse import urlparse

import tldextract

_cfg = json.load(open(Path(__file__).resolve().parent.parent / 'models' / 'feature_config.json'))

PHISH_HINTS = _cfg['phish_hints']
SHORTENER_RE = re.compile(_cfg['shortener_pattern'])
SUSPICIOUS_TLDS = set(_cfg['suspicious_tlds'])
extractor = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, no network call
SPLIT = re.compile(r'[-./?=@&%:_]')


def _word_stats(words):
    if not words:
        return 0, 0, 0, 0.0
    lens = [len(w) for w in words]
    return len(words), min(lens), max(lens), sum(lens) / len(lens)


def extract_features_v2(url):
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
        url = 'http://' + url  # users often paste URLs without a scheme
    parsed, ext = urlparse(url), extractor(url)
    host, path, low = parsed.netloc, parsed.path, url.lower()
    suffix = ext.suffix.lower()
    f = {}

    f['length_url'] = len(url)
    f['length_hostname'] = len(host)
    dotted = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host.split(':')[0]) is not None
    f['ip'] = int(dotted or re.search(r'[0-9a-fA-F]{7,}', url) is not None)

    for name, ch in [('nb_dots', '.'), ('nb_hyphens', '-'), ('nb_at', '@'), ('nb_qm', '?'),
                     ('nb_and', '&'), ('nb_or', '|'), ('nb_eq', '='), ('nb_underscore', '_'),
                     ('nb_tilde', '~'), ('nb_percent', '%'), ('nb_slash', '/'), ('nb_star', '*'),
                     ('nb_colon', ':'), ('nb_comma', ','), ('nb_semicolumn', ';'), ('nb_dollar', '$')]:
        f[name] = url.count(ch)
    f['nb_space'] = url.count(' ') + url.count('%20')
    f['nb_www'] = host.lower().count('www')
    total_com = low.count('.com')
    f['nb_com'] = max(total_com - 1, 0) if suffix == 'com' else total_com
    f['nb_dslash'] = url.count('//') - 1

    f['http_in_path'] = path.lower().count('http')
    f['https_token'] = 0 if low.startswith('https') else 1
    f['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)
    f['ratio_digits_host'] = sum(c.isdigit() for c in host) / len(host) if host else 0.0
    f['tld_in_path'] = int(bool(suffix) and suffix in path.lower())
    f['tld_in_subdomain'] = int(bool(suffix) and suffix in ext.subdomain.lower())
    f['shortening_service'] = int(SHORTENER_RE.search(low) is not None)

    host_text = f"{ext.subdomain}.{ext.domain}" if ext.subdomain else ext.domain
    path_text = path + ('?' + parsed.query if parsed.query else '')
    host_words = [w for w in SPLIT.split(host_text) if w]
    path_words = [w for w in SPLIT.split(path_text) if w]
    f['length_words_raw'], f['shortest_words_raw'], f['longest_words_raw'], f['avg_words_raw'] = \
        _word_stats(host_words + path_words)
    _, f['shortest_word_host'], f['longest_word_host'], f['avg_word_host'] = _word_stats(host_words)
    _, f['shortest_word_path'], f['longest_word_path'], f['avg_word_path'] = _word_stats(path_words)

    f['phish_hints'] = sum(low.count(w) for w in PHISH_HINTS)
    f['suspecious_tld'] = int(suffix in SUSPICIOUS_TLDS)
    return f
