#!/usr/bin/env python3
"""Safe SMTP connectivity inventory.

This program never sends MAIL FROM, RCPT TO, DATA, or email content.
It only resolves MX/A/AAAA, opens a TCP connection to port 25, reads the
banner, sends EHLO, and optionally negotiates STARTTLS.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import dns.exception
import dns.resolver
import requests

EMAIL_RE = re.compile(r"^[^@\s<>]+@([^@\s<>]+)$", re.ASCII)
DEFAULT_DATASET = os.getenv("HF_DATASET", "Valter3B/Trader_Emails")
DEFAULT_DELAY = float(os.getenv("SMTP_SCAN_DELAY", "1.0"))
DEFAULT_WORKERS = int(os.getenv("SMTP_SCAN_WORKERS", "3"))
DEFAULT_TIMEOUT = float(os.getenv("SMTP_SCAN_TIMEOUT", "8"))


@dataclass
class Result:
    domain: str
    source_count: int
    mx_hosts: str = ""
    addresses: str = ""
    dns_status: str = ""
    ptr_names: str = ""
    fcrdns: str = ""
    tcp25: str = ""
    banner_code: str = ""
    banner: str = ""
    ehlo_code: str = ""
    ehlo: str = ""
    starttls: str = "not_tested"
    error: str = ""
    tested_at_utc: str = ""


def hf_headers() -> dict[str, str]:
    token = os.getenv("HF_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def list_dataset_files(dataset: str) -> list[str]:
    url = f"https://huggingface.co/api/datasets/{dataset}/tree/main"
    files: list[str] = []
    params = {"recursive": "true", "expand": "false", "limit": "1000"}
    response = requests.get(url, headers=hf_headers(), params=params, timeout=30)
    response.raise_for_status()
    for item in response.json():
        if item.get("type") == "file" and item.get("path", "").lower().endswith((".parquet", ".csv", ".jsonl")):
            files.append(item["path"])
    if not files:
        raise RuntimeError("O dataset não contém Parquet, CSV ou JSONL acessível.")
    return files


def download_file(dataset: str, path: str, out_dir: Path) -> Path:
    target = out_dir / Path(path).name
    url = f"https://huggingface.co/datasets/{dataset}/resolve/main/{path}"
    response = requests.get(url, headers=hf_headers(), timeout=120)
    response.raise_for_status()
    target.write_bytes(response.content)
    return target


def find_email_column(columns: Iterable[str]) -> str:
    candidates = {c.lower().strip(): c for c in columns}
    for name in ("email", "e-mail", "correo", "mail", "address"):
        if name in candidates:
            return candidates[name]
    for name, original in candidates.items():
        if "email" in name or "mail" in name:
            return original
    raise RuntimeError(f"Não encontrei uma coluna de e-mail. Colunas: {list(columns)}")


def load_domains(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in files:
        if path.suffix.lower() == ".parquet":
            import pyarrow.parquet as pq
            table = pq.read_table(path)
            data = table.to_pydict()
            column = find_email_column(data.keys())
            values = data[column]
        elif path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
                reader = csv.DictReader(handle)
                column = find_email_column(reader.fieldnames or [])
                values = (row.get(column, "") for row in reader)
        else:
            values = []
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    column = find_email_column(obj.keys())
                    values.append(obj.get(column, ""))
        for value in values:
            match = EMAIL_RE.match(str(value).strip())
            if not match:
                continue
            domain = match.group(1).rstrip(".").lower()
            if domain:
                counts[domain] = counts.get(domain, 0) + 1
    return counts


def resolve_domain(domain: str, timeout: float) -> tuple[list[str], list[str], str, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    mx_hosts: list[str] = []
    addresses: list[str] = []
    ptr_names: list[str] = []
    try:
        answers = resolver.resolve(domain, "MX")
        mx_hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
    except Exception:
        mx_hosts = []
    for host in mx_hosts or [domain]:
        for rrtype in ("A", "AAAA"):
            try:
                addresses.extend(str(r) for r in resolver.resolve(host, rrtype))
            except Exception:
                pass
    addresses = sorted(set(addresses))
    if not mx_hosts and not addresses:
        return [], [], "no_dns_mx", []
    dns_status = "mx_ok" if mx_hosts else "address_without_mx"
    for ip in addresses:
        try:
            ptr_names.extend(str(x).rstrip(".") for x in resolver.resolve_address(ip))
        except Exception:
            pass
    return mx_hosts, addresses, dns_status, sorted(set(ptr_names))


def check_fcrdns(addresses: list[str], ptr_names: list[str], timeout: float) -> str:
    if not addresses:
        return "no_address"
    if not ptr_names:
        return "no_ptr"
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    reverse_forward: set[str] = set()
    for name in ptr_names:
        for rrtype in ("A", "AAAA"):
            try:
                reverse_forward.update(str(x) for x in resolver.resolve(name, rrtype))
            except Exception:
                pass
    return "pass" if set(addresses) & reverse_forward else "fail"


def read_response(sock: socket.socket) -> tuple[int, str]:
    data = b""
    sock.settimeout(DEFAULT_TIMEOUT)
    while b"\n" not in data and len(data) < 8192:
        chunk = sock.recv(2048)
        if not chunk:
            break
        data += chunk
    text = data.decode("utf-8", "replace").replace("\r", "").strip()
    first = text.splitlines()[0] if text else ""
    try:
        code = int(first[:3])
    except ValueError:
        code = 0
    return code, text[:1000]


def smtp_probe(ip: str, host: str, timeout: float) -> dict[str, str]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    result = {"tcp25": "fail", "banner_code": "", "banner": "", "ehlo_code": "", "ehlo": "", "starttls": "not_offered", "error": ""}
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, 25))
            result["tcp25"] = "connected"
            code, text = read_response(sock)
            result["banner_code"], result["banner"] = str(code), text
            if code < 200 or code >= 600:
                return result
            sock.sendall(f"EHLO connectivity-check.invalid\r\n".encode())
            code, text = read_response(sock)
            result["ehlo_code"], result["ehlo"] = str(code), text
            if code == 250 and "STARTTLS" in text.upper():
                result["starttls"] = "offered"
            sock.sendall(b"QUIT\r\n")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def inspect_domain(domain: str, count: int, timeout: float, delay: float) -> Result:
    result = Result(domain=domain, source_count=count, tested_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    try:
        mx, addresses, dns_status, ptr = resolve_domain(domain, timeout)
        result.mx_hosts = ";".join(mx)
        result.addresses = ";".join(addresses)
        result.dns_status = dns_status
        result.ptr_names = ";".join(ptr)
        result.fcrdns = check_fcrdns(addresses, ptr, timeout)
        if not addresses:
            return result
        probe = None
        for ip in addresses:
            probe = smtp_probe(ip, mx[0] if mx else domain, timeout)
            if probe["tcp25"] == "connected":
                break
        for key in ("tcp25", "banner_code", "banner", "ehlo_code", "ehlo", "starttls", "error"):
            setattr(result, key, probe.get(key, ""))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        time.sleep(delay)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--output", default="smtp_connectivity_report.csv")
    parser.add_argument("--cache-dir", default=".hf_cache")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 5:
        raise SystemExit("workers deve estar entre 1 e 5")
    cache = Path(args.cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    paths = [download_file(args.dataset, p, cache) for p in list_dataset_files(args.dataset)]
    domains = load_domains(paths)
    print(f"[INFO] Domínios únicos encontrados: {len(domains)}")
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = [pool.submit(inspect_domain, d, n, args.timeout, args.delay) for d, n in sorted(domains.items())]
        for job in as_completed(jobs):
            result = job.result()
            results.append(result)
            print(f"{result.domain}: dns={result.dns_status} tcp25={result.tcp25} ehlo={result.ehlo_code} fcrdns={result.fcrdns}")
    results.sort(key=lambda r: r.domain)
    with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()) if results else list(Result("", 0).__dict__.keys()))
        writer.writeheader()
        writer.writerows(asdict(r) for r in results)
    print(f"[OK] Relatório: {args.output}")
    print("[INFO] Nenhum MAIL FROM, RCPT TO ou DATA foi enviado.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
