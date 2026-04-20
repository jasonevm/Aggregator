#!/usr/bin/env python3
"""
Relay Config Aggregator v3
Pipeline: Fetch → Parse → Dedup → Static Score → TCP Probe → TLS Timing → Export

Timing budget on 37k unique configs:
  Stage 1 (fetch+parse):  ~5s
  Stage 2 (TCP probe):   ~15s  (top 3000 pre-filtered, 300 concurrency, 1.5s timeout)
  Stage 3 (TLS timing):  ~10s  (TLS/Reality nodes only, 200 concurrency, 3s timeout)
  Total:                 ~30-40s
"""

import asyncio
import aiohttp
import ssl
import re
import base64
import json
import time
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

TARGET_COUNT    = 100    # configs in final output
PRE_FILTER_TOP  = 3000   # static-score top N before any network test
                         # keeps TCP phase at ~15s instead of 23 minutes

FETCH_TIMEOUT   = 10     # sec, per source HTTP request
TCP_TIMEOUT     = 1.5    # sec, TCP connect probe
TLS_TIMEOUT     = 3.0    # sec, TLS handshake probe

MAX_FETCH_CONC  = 40     # parallel source fetches
MAX_TCP_CONC    = 300    # parallel TCP probes
MAX_TLS_CONC    = 200    # parallel TLS handshake probes

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
    "https://raw.githubusercontent.com/ewecrow78-gif/whitelist1/main/list.txt",
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
}

# ── LOGGING ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-7s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('relay')

# ── DATA MODEL ────────────────────────────────────────────────────────────────

@dataclass
class Config:
    protocol: str
    host:     str
    port:     int
    uid:      str
    raw:      str
    sni:      str  = ''
    security: str  = ''
    network:  str  = ''
    # network probes — populated in stages 2-3
    tcp_ms:   Optional[float] = None   # None = dead / untested
    tls_ms:   Optional[float] = None   # None = not TLS or failed

    def key(self) -> str:
        return f"{self.protocol}|{self.host.lower()}|{self.port}|{self.uid[:12]}"

    @property
    def static_score(self) -> int:
        """Score without network data — used for pre-filtering."""
        s = 0
        sec = self.security.lower()
        if sec == 'reality': s += 50
        elif sec == 'tls':   s += 25
        if self.sni and any(d in self.sni for d in WHITELIST_DOMAINS):
            s += 30
        return s

    @property
    def score(self) -> int:
        """Full score including network probes."""
        s = self.static_score
        # TCP latency: 0ms → +25, 1500ms → 0
        if self.tcp_ms is not None:
            s += max(0, 25 - int(self.tcp_ms / 60))
        # TLS handshake: bonus for low-latency TLS/Reality
        # 0ms → +20, 3000ms → 0
        if self.tls_ms is not None:
            s += max(0, 20 - int(self.tls_ms / 150))
        return s

# ── HELPERS ───────────────────────────────────────────────────────────────────

def _b64dec(s: str) -> Optional[str]:
    try:
        s = s.strip()
        pad = (-len(s)) % 4
        return base64.b64decode(s + '=' * pad).decode('utf-8', errors='replace')
    except Exception:
        return None

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
                      network=qs.get('type', [''])[0].lower())
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
                      network=str(d.get('net', '')).lower())
    except Exception: return None

def _parse_trojan(raw: str) -> Optional[Config]:
    try:
        p = urlparse(raw); qs = parse_qs(p.query)
        host = p.hostname or ''; port = p.port or 443
        if not host: return None
        return Config('trojan', host, port, p.username or '', raw,
                      sni=qs.get('sni', [''])[0] or host,
                      security='tls',
                      network=qs.get('type', [''])[0].lower())
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
        return Config('ss', host, port, uid[:20], raw,
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
        log.debug('Fetch error %s: %s', url, e)
        return []
    # Auto-detect base64 content
    sample = '\n'.join(text.splitlines()[:5])
    if not any(p in sample for p in _PREFIXES):
        decoded = _b64dec(text.replace('\n', '').replace('\r', ''))
        if decoded and any(p in decoded for p in _PREFIXES):
            text = decoded
    return [l.split('#')[0] for l in text.splitlines()
            if any(l.strip().startswith(p) for p in _PREFIXES)]

# ── STAGE 2: TCP PROBE ────────────────────────────────────────────────────────

async def _tcp_probe(cfg: Config, sem: asyncio.Semaphore) -> None:
    async with sem:
        try:
            t0 = time.monotonic()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(cfg.host, cfg.port), timeout=TCP_TIMEOUT)
            cfg.tcp_ms = round((time.monotonic() - t0) * 1000, 1)
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception: pass
        except Exception:
            cfg.tcp_ms = None  # dead

# ── STAGE 3: TLS HANDSHAKE TIMING ────────────────────────────────────────────
#
# Measures full TLS handshake time (TCP + crypto) for tls/reality nodes.
# Reality presents a legit-looking cert for the SNI domain → handshake
# completes normally with verify=False. Low TLS latency = low server load
# + good uplink. Adds up to +20 pts to score.

_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE

async def _tls_probe(cfg: Config, sem: asyncio.Semaphore) -> None:
    async with sem:
        sni = cfg.sni or cfg.host
        try:
            t0 = time.monotonic()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    cfg.host, cfg.port,
                    ssl=_TLS_CTX,
                    server_hostname=sni,
                ),
                timeout=TLS_TIMEOUT,
            )
            cfg.tls_ms = round((time.monotonic() - t0) * 1000, 1)
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except Exception: pass
        except Exception:
            cfg.tls_ms = None

# ── MAIN ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    t_start = time.monotonic()

    # ── 1. Fetch ──────────────────────────────────────────────────────────────
    log.info('Stage 1 — Fetching %d sources...', len(SOURCES))
    conn = aiohttp.TCPConnector(limit=MAX_FETCH_CONC, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        batches = await asyncio.gather(*[_fetch(session, u) for u in SOURCES])

    raw_lines = [l for b in batches for l in b]
    log.info('  raw lines: %d', len(raw_lines))

    # ── 2. Parse + dedup ──────────────────────────────────────────────────────
    seen: dict[str, Config] = {}
    bad = 0
    for line in raw_lines:
        cfg = _parse_line(line)
        if not cfg or not cfg.host or not (1 <= cfg.port <= 65535):
            bad += 1; continue
        k = cfg.key()
        if k not in seen:
            seen[k] = cfg

    unique = list(seen.values())
    log.info('  unique: %d  (dropped: %d)', len(unique), bad)

    # ── 3. Pre-filter by static score ─────────────────────────────────────────
    # Sort by static score, test only top PRE_FILTER_TOP.
    # Rationale: Reality/TLS/SNI-whitelisted configs are almost always better;
    # testing all 37k would take 23 minutes.
    unique.sort(key=lambda c: c.static_score, reverse=True)
    candidates = unique[:PRE_FILTER_TOP]
    skipped = len(unique) - len(candidates)
    log.info('Stage 2 — TCP probe: testing top %d (skipping %d low-score)',
             len(candidates), skipped)

    tcp_sem = asyncio.Semaphore(MAX_TCP_CONC)
    await asyncio.gather(*[_tcp_probe(c, tcp_sem) for c in candidates])

    alive = [c for c in candidates if c.tcp_ms is not None]
    log.info('  alive: %d  dead: %d  (%.1fs)',
             len(alive), len(candidates) - len(alive), time.monotonic() - t_start)

    # ── 4. TLS handshake timing ───────────────────────────────────────────────
    tls_candidates = [c for c in alive if c.security in ('tls', 'reality')]
    log.info('Stage 3 — TLS timing: %d nodes', len(tls_candidates))

    tls_sem = asyncio.Semaphore(MAX_TLS_CONC)
    await asyncio.gather(*[_tls_probe(c, tls_sem) for c in tls_candidates])

    tls_ok  = sum(1 for c in tls_candidates if c.tls_ms is not None)
    tls_bad = len(tls_candidates) - tls_ok
    log.info('  TLS ok: %d  failed: %d  (%.1fs)',
             tls_ok, tls_bad, time.monotonic() - t_start)

    # ── 5. Final sort + slice ─────────────────────────────────────────────────
    alive.sort(key=lambda c: c.score, reverse=True)
    final = alive[:TARGET_COUNT]

    # ── 6. Build output ───────────────────────────────────────────────────────
    ts = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())
    lines = [
        '#profile-title: Relay 100',
        '#profile-update-interval: 1',
        f'#announce: ⚡️ Relay {len(final)} configs | {ts} ⚡️',
        '#profile-web-page-url: https://github.com/jasonevm/relay',
        '',
    ]
    for i, cfg in enumerate(final):
        flag, ctry = _country(cfg.host)
        sec    = cfg.security.upper() or '—'
        sni    = cfg.sni or '—'
        tcp    = f'{cfg.tcp_ms:.0f}ms' if cfg.tcp_ms else '?'
        tls    = f'TLS:{cfg.tls_ms:.0f}ms' if cfg.tls_ms else ''
        timing = f'{tcp} {tls}'.strip()
        name   = f'{flag} {ctry} | {cfg.protocol.upper()} | {sec} | {sni} | {timing} | #{i+1}'
        lines.append(f'{cfg.raw}#{name}')

    with open('configs.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    # ── 7. Stats ──────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - t_start
    by_proto = {}; by_sec = {}; by_ctry = {}
    for c in final:
        by_proto[c.protocol]       = by_proto.get(c.protocol, 0) + 1
        by_sec[c.security or '—']  = by_sec.get(c.security or '—', 0) + 1
        _, ctry = _country(c.host)
        by_ctry[ctry]              = by_ctry.get(ctry, 0) + 1

    log.info('─' * 52)
    log.info('Saved configs.txt  (%d configs)', len(final))
    log.info('Protocol : %s', by_proto)
    log.info('Security : %s', by_sec)
    log.info('Countries: %s', sorted(by_ctry.items(), key=lambda x: -x[1])[:5])
    log.info('Total elapsed: %.1fs', elapsed)

if __name__ == '__main__':
    asyncio.run(main())
