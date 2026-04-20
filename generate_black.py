#!/usr/bin/env python3
"""
Relay Config Aggregator v4
Fetch → Parse → Dedup → TCP (ALL) → Speed Test (top alive) → Export

Timing on 37k unique configs (GitHub Actions, 2-core):
  Fetch+parse:          ~5s
  TCP probe (all 37k):  ~90s   (400 concurrency, 1.0s timeout)
  Speed test (top 500): ~150s  (30 workers, 8s per node)
  Total:                ~4 min

Requires xray binary in PATH. Add to workflow:
  wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
  unzip -q Xray-linux-64.zip xray && chmod +x xray && sudo mv xray /usr/local/bin/
"""

import asyncio
import aiohttp
import re
import os
import json
import base64
import time
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

TARGET_COUNT    = 100
FETCH_TIMEOUT   = 10
TCP_TIMEOUT     = 1.0
MAX_FETCH_CONC  = 40
MAX_TCP_CONC    = 400    # all 37k: 37k/400 * 1.0s ≈ 90s

SPEED_TEST_URL  = 'https://cachefly.cachefly.net/50mb.test'
SPEED_TEST_SECS = 8
MIN_SPEED_MBPS  = 50.0
SPEED_TEST_TOP  = 500    # speed-test top N alive (by TCP latency)
SPEED_WORKERS   = 30     # parallel xray+curl instances
SPEED_PORT_BASE = 20000  # local SOCKS5 ports 20000–20029

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/light.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
    "https://wlrus.lol/confs/blackl.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
    "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
    "https://obwl.vercel.app/sub.txt",
    "https://raw.githubusercontent.com/vsevjik/OBWLautoupd/refs/heads/main/ru_vless_reality.txt",
    "https://raw.githubusercontent.com/tankist939-afk/Obhod-WL/refs/heads/main/Obhod%20WL",
    "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/refs/heads/main/rkn_white_list",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
    "https://raw.githubusercontent.com/gergew452/Generation-Liberty/refs/heads/main/githubmirror/best.txt",
    "https://mygala.ru/vpn/premium.php",
    "https://raw.githubusercontent.com/Sanuyyq/sub-storage1/refs/heads/main/bs.txt",
    "https://gbr.mydan.online/configs",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/Svoboda",
    "https://raw.githubusercontent.com/ewecross78-gif/whitelist1/main/list.txt",
    "https://ety.twinkvibe.gay/whitelist",
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/LimeVPN.txt?v=1",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ru/vless.txt",
    "https://subrostunnel.vercel.app/gen.txt",
    "https://subrostunnel.vercel.app/wl.txt",
    "https://rostunnel.vercel.app/mega.txt",
    "https://github.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/raw/refs/heads/main/vpn-lte/WHITELIST-ALL.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/RU_Best/ru_white_all_WHITE.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/subscriptions/FreeCFGHub1.txt",
    "https://raw.githubusercontent.com/LimeHi/LimeVPNGenerator/main/Keys.txt?v=1",
    "http://livpnsub.dpdns.org/sub.php?token=20fd9e97b840e2f9",
    "https://subvpn.dpdns.org/sub.txt",
    "https://autosub-config.vercel.app/sub.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
    "https://gitverse.ru/api/repos/Vsevj/OBS/raw/branch/master/wwh",
    "https://subrostunnel.vercel.app/std.txt",
    "https://raw.githubusercontent.com/kangaroo255075-collab/KrolekVPNReborn/refs/heads/main/Whitelist.txt",
    "https://raw.githubusercontent.com/SER38Off/happ-subscription/refs/heads/main/all-servers.txt",
    "https://raw.githubusercontent.com/SER38Off/happ-subscription/refs/heads/main/all-white-sub.txt",
    "https://raw.githubusercontent.com/SER38Off/happ-subscription/refs/heads/main/all-white-lists-servers.txt",
    "https://raw.githubusercontent.com/SER38Off/happ-subscription/refs/heads/main/best-white-lists-russia.txt",
    "https://raw.githubusercontent.com/SER38Off/happ-subscription/refs/heads/main/russia-white-lists.txt",
    "https://llxickvpn.vercel.app/api/index",
    "https://raw.githubusercontent.com/clowovx/clowovxVPN/refs/heads/main/clowovxVPN",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/26.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/27.txt",
    "https://github.com/KiryaScript/white-lists/raw/refs/heads/main/githubmirror/28.txt",
    "https://raw.githubusercontent.com/pyatovsergey0105-maker/-/refs/heads/main/Whie_spiksik",
    *[f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt"
      for i in range(1, 21)],
]

WHITELIST_DOMAINS = [
    'gosuslugi.ru', 'mos.ru', 'nalog.ru', 'kremlin.ru', 'government.ru',
    'sberbank.ru', 'tbank.ru', 'alfabank.ru', 'vtb.ru', 'vk.com', 'ok.ru',
    'mail.ru', 'yandex.ru', 'dzen.ru', 'rutube.ru', 'ozon.ru', 'wildberries.ru',
    'avito.ru', 'rbc.ru', 'tass.ru', '2gis.ru', 'rzd.ru', 'hh.ru',
]

_TLD_MAP = {
    '.ir': ('🇮🇷', 'Iran'),     '.ru': ('🇷🇺', 'Russia'),  '.de': ('🇩🇪', 'Germany'),
    '.us': ('🇺🇸', 'USA'),      '.nl': ('🇳🇱', 'NL'),       '.fi': ('🇫🇮', 'Finland'),
    '.pl': ('🇵🇱', 'Poland'),   '.kz': ('🇰🇿', 'KZ'),       '.tr': ('🇹🇷', 'Turkey'),
    '.fr': ('🇫🇷', 'France'),   '.gb': ('🇬🇧', 'UK'),        '.se': ('🇸🇪', 'Sweden'),
    '.ch': ('🇨🇭', 'CH'),       '.at': ('🇦🇹', 'Austria'),  '.cz': ('🇨🇿', 'CZ'),
    '.ua': ('🇺🇦', 'Ukraine'),  '.am': ('🇦🇲', 'Armenia'),  '.ge': ('🇬🇪', 'Georgia'),
    '.az': ('🇦🇿', 'AZ'),       '.lt': ('🇱🇹', 'LT'),        '.lv': ('🇱🇻', 'LV'),
    '.ee': ('🇪🇪', 'EE'),       '.jp': ('🇯🇵', 'Japan'),    '.sg': ('🇸🇬', 'SG'),
    '.hk': ('🇭🇰', 'HK'),       '.tw': ('🇹🇼', 'Taiwan'),   '.ro': ('🇷🇴', 'Romania'),
    '.hu': ('🇭🇺', 'Hungary'),  '.sk': ('🇸🇰', 'SK'),        '.bg': ('🇧🇬', 'BG'),
    '.rs': ('🇷🇸', 'Serbia'),   '.md': ('🇲🇩', 'Moldova'),  '.ca': ('🇨🇦', 'Canada'),
    '.au': ('🇦🇺', 'AU'),        '.br': ('🇧🇷', 'Brazil'),   '.cn': ('🇨🇳', 'China'),
    '.kr': ('🇰🇷', 'Korea'),    '.in': ('🇮🇳', 'India'),     '.si': ('🇸🇮', 'SI'),
    '.no': ('🇳🇴', 'Norway'),   '.dk': ('🇩🇰', 'Denmark'),  '.pt': ('🇵🇹', 'Portugal'),
    '.es': ('🇪🇸', 'Spain'),    '.it': ('🇮🇹', 'Italy'),     '.gr': ('🇬🇷', 'Greece'),
}

_VIBES = [
    '⚡', '🔥', '🌊', '🎯', '💎', '🚀', '🌟', '🎭', '🦁', '🐉',
    '🦅', '🌈', '💫', '🏆', '🌙', '☄️', '🔮', '🛸', '⚔️', '🧬',
    '🎲', '🌺', '🦊', '🐺', '🌠', '💥', '🧲', '🎪', '🧿', '🪐',
]

# ── LOGGING ───────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s  %(levelname)-7s %(message)s',
                    datefmt='%H:%M:%S')
log = logging.getLogger('relay')

# ── DATA MODEL ────────────────────────────────────────────────────────────────

@dataclass
class Config:
    protocol: str
    host:     str
    port:     int
    uid:      str
    raw:      str
    sni:      str = ''
    security: str = ''
    network:  str = ''
    pbk:      str = ''   # reality publicKey
    sid:      str = ''   # reality shortId
    fp:       str = ''   # fingerprint
    flow:     str = ''   # xtls flow
    path:     str = ''   # ws/grpc/h2 path
    host_hdr: str = ''   # ws Host header
    tcp_ms:     Optional[float] = None
    speed_mbps: Optional[float] = None

    def key(self) -> str:
        return f"{self.protocol}|{self.host.lower()}|{self.port}|{self.uid[:12]}"

    def label(self, idx: int) -> str:
        flag, ctry = _country(self.host)
        vibe = _VIBES[abs(hash(self.key())) % len(_VIBES)]
        return f'{flag} {vibe} {ctry} #{idx + 1}'

# ── HELPERS ───────────────────────────────────────────────────────────────────

def _b64dec(s: str) -> Optional[str]:
    try:
        s = s.strip(); pad = (-len(s)) % 4
        return base64.b64decode(s + '=' * pad).decode('utf-8', errors='replace')
    except Exception: return None

def _country(host: str) -> tuple[str, str]:
    h = host.lower()
    for tld, pair in _TLD_MAP.items():
        if h.endswith(tld) or (tld + '.') in h:
            return pair
    return '🌐', 'Unknown'

# ── PARSERS ───────────────────────────────────────────────────────────────────

def _parse_vless(raw: str) -> Optional[Config]:
    try:
        p = urlparse(raw); qs = parse_qs(p.query)
        host = p.hostname or ''; port = p.port or 443
        if not host: return None
        return Config('vless', host, port, p.username or '', raw,
                      sni=qs.get('sni', [''])[0],
                      security=qs.get('security', [''])[0].lower(),
                      network=qs.get('type', [''])[0].lower(),
                      pbk=qs.get('pbk', [''])[0],
                      sid=qs.get('sid', [''])[0],
                      fp=qs.get('fp', ['chrome'])[0] or 'chrome',
                      flow=qs.get('flow', [''])[0],
                      path=qs.get('path', [''])[0],
                      host_hdr=qs.get('host', [''])[0])
    except Exception: return None

def _parse_vmess(raw: str) -> Optional[Config]:
    try:
        d = json.loads(_b64dec(raw[8:]) or 'null')
        if not d: return None
        host = str(d.get('add', '')).strip(); port = int(d.get('port', 443))
        if not host: return None
        return Config('vmess', host, port, str(d.get('id', '')), raw,
                      sni=(d.get('sni') or d.get('host') or '').strip(),
                      security='tls' if str(d.get('tls', '')).lower() == 'tls' else '',
                      network=str(d.get('net', '')).lower(),
                      path=str(d.get('path', '')),
                      host_hdr=str(d.get('host', '')))
    except Exception: return None

def _parse_trojan(raw: str) -> Optional[Config]:
    try:
        p = urlparse(raw); qs = parse_qs(p.query)
        host = p.hostname or ''; port = p.port or 443
        if not host: return None
        return Config('trojan', host, port, p.username or '', raw,
                      sni=qs.get('sni', [''])[0] or host,
                      security='tls', network=qs.get('type', [''])[0].lower(),
                      path=qs.get('path', [''])[0], fp=qs.get('fp', [''])[0])
    except Exception: return None

def _parse_ss(raw: str) -> Optional[Config]:
    try:
        p = urlparse(raw); qs = parse_qs(p.query)
        if p.hostname:
            host, port, uid = p.hostname, p.port or 8388, p.username or ''
        else:
            decoded = _b64dec(p.netloc)
            if not decoded: return None
            m = re.match(r'(.+)@([^:@]+):(\d+)$', decoded)
            if not m: return None
            uid, host, port = m.group(1), m.group(2), int(m.group(3))
        if not host: return None
        return Config('ss', host, port, uid[:40], raw,
                      sni=qs.get('sni', [''])[0], security='none',
                      network=qs.get('type', [''])[0].lower())
    except Exception: return None

_PARSERS: dict[str, callable] = {
    'vless://': _parse_vless, 'vmess://': _parse_vmess,
    'trojan://': _parse_trojan, 'ss://': _parse_ss,
}
_PREFIXES = tuple(_PARSERS)

def _parse_line(line: str) -> Optional[Config]:
    uri = line.split('#')[0].strip()
    for prefix, fn in _PARSERS.items():
        if uri.startswith(prefix):
            return fn(uri)
    return None

# ── FETCH ─────────────────────────────────────────────────────────────────────

async def _fetch(session: aiohttp.ClientSession, url: str) -> list[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
                               ssl=False, allow_redirects=True) as r:
            if r.status != 200: return []
            text = (await r.text(errors='replace')).strip()
    except Exception as e:
        log.debug('fetch %s: %s', url, e); return []
    sample = '\n'.join(text.splitlines()[:5])
    if not any(p in sample for p in _PREFIXES):
        decoded = _b64dec(text.replace('\n', '').replace('\r', ''))
        if decoded and any(p in decoded for p in _PREFIXES):
            text = decoded
    return [l.split('#')[0] for l in text.splitlines()
            if any(l.strip().startswith(p) for p in _PREFIXES)]

# ── TCP PROBE ─────────────────────────────────────────────────────────────────

async def _tcp_probe(cfg: Config, sem: asyncio.Semaphore) -> None:
    async with sem:
        try:
            t0 = time.monotonic()
            _, w = await asyncio.wait_for(
                asyncio.open_connection(cfg.host, cfg.port), timeout=TCP_TIMEOUT)
            cfg.tcp_ms = round((time.monotonic() - t0) * 1000, 1)
            w.close()
            try: await asyncio.wait_for(w.wait_closed(), timeout=0.3)
            except Exception: pass
        except Exception: cfg.tcp_ms = None

# ── XRAY CONFIG BUILDER ───────────────────────────────────────────────────────

def _stream_settings(cfg: Config) -> dict:
    sec = cfg.security.lower(); net = cfg.network.lower() or 'tcp'
    ss: dict = {'network': net}
    if sec == 'reality':
        ss['security'] = 'reality'
        ss['realitySettings'] = {
            'serverName': cfg.sni, 'fingerprint': cfg.fp or 'chrome',
            'publicKey': cfg.pbk, 'shortId': cfg.sid,
        }
    elif sec == 'tls':
        ss['security'] = 'tls'
        ss['tlsSettings'] = {
            'serverName': cfg.sni, 'allowInsecure': True,
            'fingerprint': cfg.fp or '',
        }
    if net == 'ws':
        ss['wsSettings'] = {
            'path': cfg.path or '/',
            'headers': {'Host': cfg.host_hdr or cfg.sni or cfg.host},
        }
    elif net == 'grpc':
        ss['grpcSettings'] = {'serviceName': cfg.path or ''}
    elif net in ('h2', 'http'):
        ss['httpSettings'] = {
            'host': [cfg.host_hdr or cfg.sni or cfg.host],
            'path': cfg.path or '/',
        }
    return ss

def _xray_config(cfg: Config, port: int) -> dict:
    inbound = {'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
               'settings': {'auth': 'noauth', 'udp': False}}
    if cfg.protocol == 'vless':
        out = {'protocol': 'vless',
               'settings': {'vnext': [{'address': cfg.host, 'port': cfg.port,
                   'users': [{'id': cfg.uid, 'encryption': 'none', 'flow': cfg.flow}]}]},
               'streamSettings': _stream_settings(cfg)}
    elif cfg.protocol == 'vmess':
        out = {'protocol': 'vmess',
               'settings': {'vnext': [{'address': cfg.host, 'port': cfg.port,
                   'users': [{'id': cfg.uid, 'alterId': 0, 'security': 'auto'}]}]},
               'streamSettings': _stream_settings(cfg)}
    elif cfg.protocol == 'trojan':
        out = {'protocol': 'trojan',
               'settings': {'servers': [{'address': cfg.host, 'port': cfg.port,
                   'password': cfg.uid}]},
               'streamSettings': _stream_settings(cfg)}
    elif cfg.protocol == 'ss':
        method, password = (cfg.uid.split(':', 1) if ':' in cfg.uid
                            else ('aes-256-gcm', cfg.uid))
        out = {'protocol': 'shadowsocks',
               'settings': {'servers': [{'address': cfg.host, 'port': cfg.port,
                   'method': method, 'password': password}]}}
    else:
        raise ValueError(cfg.protocol)
    return {'log': {'loglevel': 'none'}, 'inbounds': [inbound],
            'outbounds': [out, {'protocol': 'freedom', 'tag': 'direct'}]}

# ── SPEED TEST ────────────────────────────────────────────────────────────────

async def _speed_test(cfg: Config, port: int) -> Optional[float]:
    cfg_path = f'/tmp/relay_{port}.json'
    proc = None
    try:
        with open(cfg_path, 'w') as f:
            json.dump(_xray_config(cfg, port), f)
        proc = await asyncio.create_subprocess_exec(
            'xray', 'run', '-c', cfg_path,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.sleep(0.7)   # wait for xray SOCKS5 bind
        curl = await asyncio.create_subprocess_exec(
            'curl', '--silent',
            '--proxy', f'socks5h://127.0.0.1:{port}',
            '--max-time', str(SPEED_TEST_SECS),
            '--connect-timeout', '3',
            '--output', '/dev/null',
            '--write-out', '%{speed_download}',
            SPEED_TEST_URL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            stdout, _ = await asyncio.wait_for(curl.communicate(),
                                               timeout=SPEED_TEST_SECS + 6)
        except asyncio.TimeoutError:
            try: curl.kill()
            except ProcessLookupError: pass
            return None
        mbps = float(stdout.decode().strip() or '0') * 8 / 1_000_000
        return round(mbps, 1) if mbps >= MIN_SPEED_MBPS else None
    except Exception as e:
        log.debug('speed port=%d: %s', port, e); return None
    finally:
        if proc:
            try: proc.kill()
            except ProcessLookupError: pass
            try: await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception: pass
        try: os.unlink(cfg_path)
        except Exception: pass

async def _run_speed_tests(candidates: list[Config]) -> list[Config]:
    port_q: asyncio.Queue[int] = asyncio.Queue()
    for i in range(SPEED_WORKERS):
        await port_q.put(SPEED_PORT_BASE + i)
    done = 0; total = len(candidates)

    async def worker(cfg: Config) -> None:
        nonlocal done
        port = await port_q.get()
        try: cfg.speed_mbps = await _speed_test(cfg, port)
        finally:
            await port_q.put(port); done += 1
            if done % 50 == 0 or done == total:
                passed = sum(1 for c in candidates[:done] if c.speed_mbps)
                log.info('  speed %d/%d  ≥%.0fMbps: %d', done, total, MIN_SPEED_MBPS, passed)

    await asyncio.gather(*[worker(c) for c in candidates])
    return [c for c in candidates if c.speed_mbps is not None]

# ── MAIN ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    t0 = time.monotonic()

    log.info('Stage 1 — fetching %d sources', len(SOURCES))
    conn = aiohttp.TCPConnector(limit=MAX_FETCH_CONC, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        batches = await asyncio.gather(*[_fetch(session, u) for u in SOURCES])
    raw_lines = [l for b in batches for l in b]
    log.info('  raw: %d  (%.1fs)', len(raw_lines), time.monotonic() - t0)

    seen: dict[str, Config] = {}; bad = 0
    for line in raw_lines:
        cfg = _parse_line(line)
        if not cfg or not cfg.host or not (1 <= cfg.port <= 65535): bad += 1; continue
        k = cfg.key()
        if k not in seen: seen[k] = cfg
    unique = list(seen.values())
    log.info('  unique: %d  dropped: %d  (%.1fs)', len(unique), bad, time.monotonic() - t0)

    log.info('Stage 2 — TCP probe: all %d (conc=%d, timeout=%.1fs)',
             len(unique), MAX_TCP_CONC, TCP_TIMEOUT)
    tcp_sem = asyncio.Semaphore(MAX_TCP_CONC)
    await asyncio.gather(*[_tcp_probe(c, tcp_sem) for c in unique])
    alive = sorted([c for c in unique if c.tcp_ms is not None], key=lambda c: c.tcp_ms)
    log.info('  alive: %d  dead: %d  (%.1fs)',
             len(alive), len(unique) - len(alive), time.monotonic() - t0)

    candidates = alive[:SPEED_TEST_TOP]
    log.info('Stage 3 — speed test: top %d (workers=%d, max=%.0fMbps, min=%.0fMbps)',
             len(candidates), SPEED_WORKERS, 5000.0, MIN_SPEED_MBPS)
    fast = await _run_speed_tests(candidates)
    fast.sort(key=lambda c: c.speed_mbps, reverse=True)
    log.info('  passed: %d  (%.1fs)', len(fast), time.monotonic() - t0)

    final = fast[:TARGET_COUNT]
    # Backfill if speed test returned fewer than TARGET_COUNT
    if len(final) < TARGET_COUNT:
        tested_keys = {c.key() for c in candidates}
        extras = [c for c in alive[SPEED_TEST_TOP:] if c.key() not in tested_keys]
        need = TARGET_COUNT - len(final)
        final += extras[:need]
        if need: log.info('  backfilled %d from non-speed-tested alive pool', need)

    ts = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())
    lines = [
        '#profile-title: Relay',
        '#profile-update-interval: 1',
        f'#announce: ⚡️ Relay {len(final)} | {ts} ⚡️',
        '#profile-web-page-url: https://github.com/jasonevm/relay',
        '',
    ]
    for i, cfg in enumerate(final):
        lines.append(f'{cfg.raw}#{cfg.label(i)}')
    with open('configs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    by_proto = {}; by_sec = {}; by_ctry = {}; speeds = []
    for c in final:
        by_proto[c.protocol]      = by_proto.get(c.protocol, 0) + 1
        by_sec[c.security or '—'] = by_sec.get(c.security or '—', 0) + 1
        _, ctry = _country(c.host); by_ctry[ctry] = by_ctry.get(ctry, 0) + 1
        if c.speed_mbps: speeds.append(c.speed_mbps)

    log.info('─' * 54)
    log.info('configs.txt  (%d configs)', len(final))
    log.info('Protocol : %s', by_proto)
    log.info('Security : %s', by_sec)
    log.info('Countries: %s', sorted(by_ctry.items(), key=lambda x: -x[1])[:5])
    if speeds:
        log.info('Speed    : min=%.0f avg=%.0f max=%.0f Mbps',
                 min(speeds), sum(speeds)/len(speeds), max(speeds))
    log.info('Total    : %.1fs', time.monotonic() - t0)

if __name__ == '__main__':
    asyncio.run(main())
