#!/usr/bin/env python3
"""
domain_recon.py — Orquestrador de recon + testes ativos (XSS/SQLi/SSTI) para bug bounty.

USO:
    python3 domain_recon.py alvo.com
    python3 domain_recon.py alvo.com --skip-fuzz --threads 40

ATENÇÃO:
    Use isto SOMENTE em domínios para os quais você tem autorização explícita
    (programa de bug bounty, contrato de pentest, ambiente próprio de laboratório).
    O script não valida escopo/autorização — isso é responsabilidade de quem executa.

Ferramentas externas usadas (se instaladas): subfinder, sublist3r, ffuf, dirb/dirbuster,
nuclei, nmap, wafw00f, katana. Nenhuma delas é chamada se não estiver no PATH.

Dependências Python: requests (pip install requests --break-system-packages)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse as urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
except ImportError:
    print("[!] Instale 'requests': pip install requests --break-system-packages")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"; M = "\033[95m"; N = "\033[0m"; BOLD = "\033[1m"

def banner(msg):
    print(f"\n{C.B}{C.BOLD}==> {msg}{C.N}")

def ok(msg):
    print(f"{C.G}[+]{C.N} {msg}")

def warn(msg):
    print(f"{C.Y}[!]{C.N} {msg}")

def bad(msg):
    print(f"{C.R}[x]{C.N} {msg}")

def has_tool(name):
    return shutil.which(name) is not None

def run(cmd, timeout=None):
    """Executa comando e retorna stdout como string. Não levanta exceção em falha."""
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                            text=True, timeout=timeout)
        if p.returncode != 0 and p.stderr:
            warn(f"comando retornou código {p.returncode}: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        return p.stdout
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        warn(f"timeout: {cmd}")
        return ""

def save(outdir, filename, content):
    path = os.path.join(outdir, filename)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Fase 1: Enumeração de subdomínios
# ---------------------------------------------------------------------------

def enum_subdomains(domain, outdir):
    banner("Enumeração de subdomínios")
    found = set()

    if has_tool("subfinder"):
        ok("rodando subfinder...")
        out = run(["subfinder", "-d", domain, "-silent"], timeout=300)
        save(outdir, "subfinder.txt", out)
        found.update(l.strip() for l in out.splitlines() if l.strip())
    else:
        warn("subfinder não encontrado, pulando")

    if has_tool("sublist3r"):
        ok("rodando sublist3r...")
        tmp = os.path.join(outdir, "sublist3r_raw.txt")
        run(["sublist3r", "-d", domain, "-o", tmp], timeout=300)
        if os.path.exists(tmp):
            with open(tmp) as f:
                found.update(l.strip() for l in f if l.strip() and "." in l)
    else:
        warn("sublist3r não encontrado, pulando")

    found.add(domain)
    save(outdir, "subdomains.txt", "\n".join(sorted(found)))
    ok(f"{len(found)} subdomínios únicos coletados")
    return sorted(found)


def probe_alive(subdomains, outdir, threads=30):
    """Verifica quais subdomínios respondem em http/https usando requests (fallback sem httpx)."""
    banner("Verificando hosts ativos")
    alive = []

    def check(host):
        for scheme in ("https://", "http://"):
            url = scheme + host
            try:
                r = requests.get(url, timeout=6, allow_redirects=True, verify=False)
                return (host, url, r.status_code)
            except requests.RequestException:
                continue
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(check, h) for h in subdomains]
        for f in as_completed(futs):
            res = f.result()
            if res:
                host, url, code = res
                alive.append(url)
                ok(f"{url} [{code}]")

    save(outdir, "alive.txt", "\n".join(alive))
    return alive


# ---------------------------------------------------------------------------
# Fase 2: WAF detection
# ---------------------------------------------------------------------------

def detect_waf(alive_urls, outdir):
    banner("Detecção de WAF (wafw00f)")
    if not has_tool("wafw00f"):
        warn("wafw00f não encontrado, pulando")
        return
    results = []
    for url in alive_urls[:20]:  # limite pra não explodir tempo
        out = run(["wafw00f", url], timeout=60)
        results.append(out)
        for line in out.splitlines():
            if "is behind" in line.lower() or "waf" in line.lower():
                ok(line.strip())
    save(outdir, "wafw00f.txt", "\n".join(results))


# ---------------------------------------------------------------------------
# Fase 3: Port scan
# ---------------------------------------------------------------------------

def port_scan(domain, outdir):
    banner("Scan de portas (nmap)")
    if not has_tool("nmap"):
        warn("nmap não encontrado, pulando")
        return
    out = run(["nmap", "-T4", "-sV", "--top-ports", "1000", domain], timeout=600)
    save(outdir, "nmap.txt", out)
    ok("nmap concluído")


# ---------------------------------------------------------------------------
# Fase 4: Crawling (katana) para descobrir URLs com parâmetros
# ---------------------------------------------------------------------------

def crawl_urls(alive_urls, outdir):
    banner("Crawling com katana")
    all_urls = set()
    if has_tool("katana"):
        for url in alive_urls:
            ok(f"crawling {url}")
            out = run(["katana", "-u", url, "-silent", "-d", "3"], timeout=180)
            all_urls.update(l.strip() for l in out.splitlines() if l.strip())
    else:
        warn("katana não encontrado, pulando crawling")
    save(outdir, "crawled_urls.txt", "\n".join(sorted(all_urls)))
    ok(f"{len(all_urls)} URLs coletadas")
    return sorted(all_urls)


# ---------------------------------------------------------------------------
# Fase 5: Fuzzing de diretórios/arquivos (ffuf / dirb)
# ---------------------------------------------------------------------------

DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

def find_wordlist():
    for w in DEFAULT_WORDLISTS:
        if os.path.exists(w):
            return w
    return None

def fuzz_dirs(alive_urls, outdir, threads=40, wordlist=None):
    banner("Fuzzing de diretórios (ffuf / dirb)")
    wordlist = wordlist or find_wordlist()
    if not wordlist:
        warn("nenhuma wordlist encontrada (informe com --wordlist), pulando fuzzing")
        return

    for url in alive_urls:
        base = url.rstrip("/")
        if has_tool("ffuf"):
            ok(f"ffuf em {base}")
            outfile = os.path.join(outdir, f"ffuf_{safe_name(base)}.json")
            run(["ffuf", "-u", f"{base}/FUZZ", "-w", wordlist, "-t", str(threads),
                 "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", outfile,
                 "-silent"], timeout=600)
        elif has_tool("dirb"):
            ok(f"dirb em {base}")
            outfile = os.path.join(outdir, f"dirb_{safe_name(base)}.txt")
            out = run(["dirb", base, wordlist, "-S"], timeout=600)
            save(outdir, os.path.basename(outfile), out)
        else:
            warn("nenhuma ferramenta de fuzzing (ffuf/dirb) encontrada")
            return

def safe_name(url):
    return re.sub(r"[^a-zA-Z0-9]+", "_", url)[:80]


# ---------------------------------------------------------------------------
# Fase 6: Nuclei (templates de vulnerabilidades conhecidas)
# ---------------------------------------------------------------------------

def run_nuclei(alive_urls, outdir):
    banner("Scan com nuclei")
    if not has_tool("nuclei"):
        warn("nuclei não encontrado, pulando")
        return
    targets_file = save(outdir, "nuclei_targets.txt", "\n".join(alive_urls))
    outfile = os.path.join(outdir, "nuclei_results.txt")
    run(["nuclei", "-l", targets_file, "-o", outfile, "-severity",
         "low,medium,high,critical", "-silent"], timeout=1800)
    if os.path.exists(outfile):
        with open(outfile) as f:
            content = f.read()
        if content.strip():
            for line in content.splitlines():
                ok(line)
        else:
            ok("nenhum finding do nuclei")


# ---------------------------------------------------------------------------
# Fase 7: Extração de parâmetros e testes ativos (XSS / SQLi / SSTI)
# ---------------------------------------------------------------------------

def extract_param_urls(urls):
    """Retorna apenas URLs que possuem query string (candidatas a teste de parâmetro)."""
    out = []
    for u in urls:
        parsed = urlparse.urlparse(u)
        if parsed.query:
            out.append(u)
    return out


XSS_PAYLOAD = "<sCr1pt>alert(1337)</sCr1pt>"
SSTI_PAYLOADS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "<%= 7*7 %>": "49",
}
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--+"]
SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"unclosed quotation mark", r"pg_query\(\)",
    r"sqlite3\.OperationalError", r"ORA-\d{5}", r"Warning: mysql", r"SQLSTATE\[",
]

def test_xss(url, param, session):
    parsed = urlparse.urlparse(url)
    qs = urlparse.parse_qs(parsed.query)
    qs[param] = [XSS_PAYLOAD]
    new_query = urlparse.urlencode(qs, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()
    try:
        r = session.get(test_url, timeout=8, verify=False)
        if XSS_PAYLOAD in r.text:
            return {"type": "XSS", "url": test_url, "param": param, "evidence": "payload refletido sem sanitização"}
    except requests.RequestException:
        pass
    return None

def test_sqli(url, param, session):
    parsed = urlparse.urlparse(url)
    qs = urlparse.parse_qs(parsed.query)
    for payload in SQLI_PAYLOADS:
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlparse.urlencode(test_qs, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            r = session.get(test_url, timeout=8, verify=False)
            body_lower = r.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    return {"type": "SQLi", "url": test_url, "param": param,
                             "evidence": f"padrão de erro SQL detectado ({pattern})"}
        except requests.RequestException:
            continue
    return None

def test_ssti(url, param, session):
    parsed = urlparse.urlparse(url)
    qs = urlparse.parse_qs(parsed.query)
    for payload, expected in SSTI_PAYLOADS.items():
        test_qs = dict(qs)
        test_qs[param] = [payload]
        new_query = urlparse.urlencode(test_qs, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            r = session.get(test_url, timeout=8, verify=False)
            if expected in r.text and payload not in r.text:
                return {"type": "SSTI", "url": test_url, "param": param,
                         "evidence": f"'{payload}' avaliado para '{expected}'"}
        except requests.RequestException:
            continue
    return None


def active_param_tests(param_urls, outdir, threads=10):
    banner("Testes ativos em parâmetros (XSS / SQLi / SSTI)")
    if not param_urls:
        warn("nenhuma URL com parâmetros encontrada para testar")
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (recon-script; authorized-testing)"})
    findings = []

    jobs = []
    for url in param_urls:
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qs(parsed.query)
        for param in params:
            jobs.append((url, param))

    ok(f"{len(jobs)} combinações url+parâmetro a testar")

    def worker(job):
        url, param = job
        local_findings = []
        for fn in (test_xss, test_sqli, test_ssti):
            res = fn(url, param, session)
            if res:
                local_findings.append(res)
        return local_findings

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(worker, j) for j in jobs]
        for f in as_completed(futs):
            for res in f.result():
                findings.append(res)
                bad(f"POSSÍVEL {res['type']} em {res['url']} (param={res['param']}) — {res['evidence']}")

    save(outdir, "vuln_findings.json", json.dumps(findings, indent=2, ensure_ascii=False))
    if not findings:
        ok("nenhum achado nos testes ativos (confirme manualmente antes de descartar)")
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Recon + testes ativos para bug bounty (uso autorizado apenas)")
    parser.add_argument("domain", help="domínio alvo, ex: exemplo.com")
    parser.add_argument("--outdir", default=None, help="diretório de saída (default: resultados_<domain>_<timestamp>)")
    parser.add_argument("--threads", type=int, default=30, help="threads para probing/fuzzing/testes")
    parser.add_argument("--wordlist", default=None, help="wordlist customizada para ffuf/dirb")
    parser.add_argument("--skip-subenum", action="store_true", help="pula enumeração de subdomínios")
    parser.add_argument("--skip-waf", action="store_true", help="pula detecção de WAF")
    parser.add_argument("--skip-portscan", action="store_true", help="pula nmap")
    parser.add_argument("--skip-crawl", action="store_true", help="pula katana")
    parser.add_argument("--skip-fuzz", action="store_true", help="pula ffuf/dirb")
    parser.add_argument("--skip-nuclei", action="store_true", help="pula nuclei")
    parser.add_argument("--skip-active-tests", action="store_true", help="pula testes de XSS/SQLi/SSTI")
    args = parser.parse_args()

    domain = args.domain.strip()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = args.outdir or f"resultados_{domain}_{timestamp}"
    os.makedirs(outdir, exist_ok=True)

    print(f"{C.BOLD}{C.M}Alvo: {domain}{C.N}")
    print(f"{C.BOLD}Saída: {outdir}{C.N}")
    print(f"{C.Y}Lembrete: só rode isso em alvos com autorização explícita.{C.N}")

    requests.packages.urllib3.disable_warnings()

    subdomains = [domain]
    if not args.skip_subenum:
        subdomains = enum_subdomains(domain, outdir)

    alive = probe_alive(subdomains, outdir, threads=args.threads)
    if not alive:
        bad("nenhum host ativo encontrado, encerrando")
        return

    if not args.skip_waf:
        detect_waf(alive, outdir)

    if not args.skip_portscan:
        port_scan(domain, outdir)

    crawled = []
    if not args.skip_crawl:
        crawled = crawl_urls(alive, outdir)

    if not args.skip_fuzz:
        fuzz_dirs(alive, outdir, threads=args.threads, wordlist=args.wordlist)

    if not args.skip_nuclei:
        run_nuclei(alive, outdir)

    if not args.skip_active_tests:
        param_urls = extract_param_urls(crawled + alive)
        active_param_tests(param_urls, outdir, threads=min(args.threads, 15))

    banner(f"Concluído. Resultados em: {outdir}")


if __name__ == "__main__":
    main()
