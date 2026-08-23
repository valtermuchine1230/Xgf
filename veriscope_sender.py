#!/usr/bin/env python3
"""
Veriscope SMTP Engine – Versão Completa de Teste
Cria: alex@sub001.veriscope0.dedyn.io
Envia para: Macuacuavalter71@gmail.com e Info1yenom@gmail.com
IPv6 atual: 2a11:6c7:f35:dd::10
"""

from __future__ import annotations
import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

import requests
from huggingface_hub import HfApi
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import dkim
import aiosmtplib
import asyncio

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("veriscope.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("veriscope")

# ---------------------------------------------------------------------------
# Configuração fixa
# ---------------------------------------------------------------------------
DOMAIN = "veriscope0.dedyn.io"
SUB = "sub001"
FULL_DOMAIN = f"{SUB}.{DOMAIN}"
EMAIL_ADDRESS = f"alex@{FULL_DOMAIN}"
SELECTOR = "s2026"
IPV6 = "2a11:6c7:f35:dd::10"          # ← Novo prefixo do túnel Toronto

TARGET_EMAILS = [
    "Macuacuavalter71@gmail.com",
    "Info1yenom@gmail.com",
]

class Config:
    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN")
        self.hf_repo = os.getenv("HF_REPO", "Valter3B/veriscope_checkpoints")
        self.desec_tokens = [
            os.getenv(f"DESEC_TOKEN_{i}")
            for i in range(1, 27)
            if os.getenv(f"DESEC_TOKEN_{i}")
        ]
        self.route64_key = os.getenv("ROUTE64_API_KEY")
        self.route64_url = os.getenv(
            "ROUTE64_API_URL", "https://manager.route64.org/api"
        ).rstrip("/")
        self.kumomta_host = os.getenv("KUMOMTA_HOST", "127.0.0.1")
        self.kumomta_port = int(os.getenv("KUMOMTA_PORT", "2525"))
        self.from_name = os.getenv("KUMOMTA_FROM_NAME", "Alex | Veriscope")

        self.data_dir = Path("data")
        self.data_dir.mkdir(exist_ok=True)
        self.account_file = self.data_dir / "account.json"

        self._validate()

    def _validate(self):
        missing = []
        if not self.hf_token:
            missing.append("HF_TOKEN")
        if not self.desec_tokens:
            missing.append("DESEC_TOKEN_1..26")
        if not self.route64_key:
            missing.append("ROUTE64_API_KEY")
        if missing:
            logger.error(f"FALHA DE CONFIGURAÇÃO: {', '.join(missing)}")
            sys.exit(1)
        logger.info(
            f"Config OK | domínio={DOMAIN} | tokens={len(self.desec_tokens)} | "
            f"Route64={self.route64_url} | IPv6={IPV6}"
        )

config = Config()

class VeriscopeError(Exception):
    def __init__(self, message: str, **ctx):
        super().__init__(f"{message} | {ctx}" if ctx else message)

# ---------------------------------------------------------------------------
# deSEC Client
# ---------------------------------------------------------------------------
class DesecClient:
    BASE = "https://desec.io/api/v1"

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.idx = 0
        self.session = requests.Session()
        self.last = 0.0

    def _token(self):
        t = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return t

    def _req(self, method, path, **kw):
        elapsed = time.time() - self.last
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Token {self._token()}"
        headers.setdefault("Content-Type", "application/json")
        url = f"{self.BASE}{path}"
        try:
            r = self.session.request(method, url, headers=headers, timeout=30, **kw)
            self.last = time.time()
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 60))
                logger.warning(f"deSEC 429 → esperando {wait}s")
                time.sleep(wait + 2)
                return self._req(method, path, **kw)
            return r
        except requests.RequestException as e:
            raise VeriscopeError("Falha de rede deSEC", error=str(e))

    def create_rrsets(self, rrsets: List[Dict]):
        logger.info(f"deSEC → publicando {len(rrsets)} RRsets em {DOMAIN}")
        r = self._req("PUT", f"/domains/{DOMAIN}/rrsets/", json=rrsets)
        if r.status_code not in (200, 201, 204):
            raise VeriscopeError(
                "deSEC falhou",
                status=r.status_code,
                body=r.text[:500],
            )
        logger.info("deSEC → RRsets publicados com sucesso")

# ---------------------------------------------------------------------------
# Route64 Client (nunca derruba o processo)
# ---------------------------------------------------------------------------
class Route64Client:
    def __init__(self, key: str, base: str):
        self.key = key
        self.base = base
        self.s = requests.Session()

    def create_ptr(self, ipv6: str, hostname: str) -> bool:
        logger.info(f"Route64 → tentando PTR {ipv6} → {hostname}")
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        try:
            r = self.s.post(
                f"{self.base}/rdns/create/",
                headers=headers,
                json={"ip": ipv6, "hostname": hostname},
                timeout=20,
            )
            if r.status_code in (200, 201):
                logger.info("Route64 → PTR criado com sucesso")
                return True

            r = self.s.put(
                f"{self.base}/rdns/{ipv6}/",
                headers=headers,
                json={"hostname": hostname},
                timeout=20,
            )
            if r.status_code in (200, 201):
                logger.info("Route64 → PTR criado com sucesso (PUT)")
                return True

            logger.warning(
                f"Route64 PTR falhou (status {r.status_code}): {r.text[:300]}"
            )
            return False
        except Exception as e:
            logger.warning(f"Route64 PTR falhou (rede): {e}")
            return False

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------
class DKIMManager:
    @staticmethod
    def generate() -> Tuple[str, str]:
        priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pub = priv.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        lines = [l for l in pub_pem.splitlines() if not l.startswith("-----")]
        return priv_pem, "".join(lines)

    @staticmethod
    def sign(msg: bytes, domain: str, selector: str, priv_pem: str) -> bytes:
        return dkim.sign(
            msg,
            selector.encode(),
            domain.encode(),
            priv_pem.encode(),
            include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
            canonicalize=(b"relaxed", b"relaxed"),
        )

# ---------------------------------------------------------------------------
# Criar conta profissional
# ---------------------------------------------------------------------------
def create_account() -> Dict:
    logger.info("=== CRIANDO CONTA PROFISSIONAL ===")
    logger.info(f"Endereço: {EMAIL_ADDRESS}")
    logger.info(f"IPv6: {IPV6}")

    desec = DesecClient(config.desec_tokens)
    route64 = Route64Client(config.route64_key, config.route64_url)

    priv_pem, pub_b64 = DKIMManager.generate()
    logger.info("Chave DKIM 2048-bit gerada")

    rrsets = [
        {
            "subname": SUB,
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"v=spf1 ip6:{IPV6}/128 -all"'],
        },
        {
            "subname": f"{SELECTOR}._domainkey.{SUB}",
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"v=DKIM1; k=rsa; p={pub_b64}"'],
        },
        {
            "subname": f"_dmarc.{SUB}",
            "type": "TXT",
            "ttl": 3600,
            "records": ['"v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r"'],
        },
        {
            "subname": SUB,
            "type": "AAAA",
            "ttl": 3600,
            "records": [IPV6],
        },
    ]

    desec.create_rrsets(rrsets)

    # PTR (não bloqueia se falhar)
    route64.create_ptr(IPV6, FULL_DOMAIN)

    account = {
        "id": "email_0001",
        "address": EMAIL_ADDRESS,
        "domain": FULL_DOMAIN,
        "ipv6": IPV6,
        "dkim_selector": SELECTOR,
        "dkim_private_pem": priv_pem,
        "dkim_public_b64": pub_b64,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(config.account_file, "w") as f:
        json.dump(account, f, indent=2)

    try:
        api = HfApi(token=config.hf_token)
        api.upload_file(
            path_or_fileobj=str(config.account_file),
            path_in_repo="accounts/email_0001.json",
            repo_id=config.hf_repo,
            repo_type="dataset",
            commit_message="Conta alex@sub001.veriscope0.dedyn.io criada",
        )
        logger.info("Conta enviada para HuggingFace")
    except Exception as e:
        logger.warning(f"Upload HF (não crítico): {e}")

    logger.info(f"✓ Conta criada: {EMAIL_ADDRESS}")
    return account

# ---------------------------------------------------------------------------
# Enviar e-mail
# ---------------------------------------------------------------------------
async def send_email(account: Dict, to_addr: str) -> str:
    logger.info(f"Enviando para {to_addr}…")

    subject = f"Veriscope – Teste de Deliverability ({datetime.now().strftime('%H:%M')})"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0; padding:0; background:#0a0a0a; font-family:Arial,Helvetica,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a; padding:40px 0;">
        <tr>
          <td align="center">
            <table width="560" cellpadding="0" cellspacing="0" style="background:#111111; border-radius:12px; border:1px solid #2a2a2a;">
              <tr>
                <td style="padding:32px 40px 24px; text-align:center; border-bottom:1px solid #222;">
                  <div style="display:inline-block; width:64px; height:64px; border:2px solid #C9A567; border-radius:50%; line-height:60px; color:#C9A567; font-size:28px; font-weight:bold;">◆</div>
                  <div style="margin-top:12px; color:#F5F5F3; font-size:22px; font-weight:700; letter-spacing:6px;">VERISCOPE</div>
                </td>
              </tr>
              <tr>
                <td style="padding:36px 40px; color:#e0e0e0; font-size:15px; line-height:1.7;">
                  <p style="margin:0 0 16px; color:#C9A567; font-size:13px; letter-spacing:1px; text-transform:uppercase;">Teste de Deliverability</p>
                  <h2 style="margin:0 0 20px; color:#ffffff; font-size:22px;">Sistema operacional</h2>
                  <p style="margin:0 0 16px;">Este é um e-mail de teste enviado pelo motor SMTP Veriscope.</p>
                  <p style="margin:0 0 8px;"><strong style="color:#C9A567;">Conta de envio:</strong><br><span style="color:#ffffff;">{account['address']}</span></p>
                  <p style="margin:0 0 8px;"><strong style="color:#C9A567;">IPv6:</strong><br><code style="color:#aaa;">{account['ipv6']}</code></p>
                  <p style="margin:0 0 24px;"><strong style="color:#C9A567;">Horário (UTC):</strong><br>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</p>
                  <p style="margin:0; color:#999; font-size:13px;">Se este e-mail chegou à caixa de entrada (não ao spam), a autenticação SPF + DKIM + DMARC está a funcionar.</p>
                </td>
              </tr>
              <tr>
                <td style="padding:20px 40px; background:#0d0d0d; border-top:1px solid #222; text-align:center;">
                  <p style="margin:0; color:#666; font-size:12px;">Alex | Veriscope<br><span style="color:#444;">Teste automático – pode ignorar</span></p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{config.from_name} <{account['address']}>"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=account["domain"])
    msg.attach(MIMEText(html, "html", "utf-8"))

    raw = msg.as_bytes()
    signed = DKIMManager.sign(
        raw,
        domain=account["domain"],
        selector=account["dkim_selector"],
        priv_pem=account["dkim_private_pem"],
    )

    try:
        smtp = aiosmtplib.SMTP(
            hostname=config.kumomta_host,
            port=config.kumomta_port,
            timeout=40,
            use_tls=False,
            start_tls=False,
            validate_certs=False,
        )
        await smtp.connect()
        await smtp.sendmail(account["address"], [to_addr], signed)
        await smtp.quit()
        logger.info(f"✓ Enviado com sucesso → {to_addr}")
        return "250 OK"
    except aiosmtplib.SMTPResponseException as e:
        logger.error(f"SMTP {e.code} → {to_addr}: {e.message}")
        return f"{e.code} {e.message}"
    except Exception as e:
        raise VeriscopeError("Falha SMTP", to=to_addr, error=str(e))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(description="Veriscope SMTP – Teste Completo")
    parser.add_argument("--provision", action="store_true", help="Criar a conta")
    parser.add_argument("--send", action="store_true", help="Enviar os e-mails")
    parser.add_argument("--full", action="store_true", help="Criar + Enviar")
    args = parser.parse_args()

    if not any([args.provision, args.send, args.full]):
        parser.print_help()
        sys.exit(0)

    try:
        account = None

        if args.provision or args.full:
            account = create_account()
            logger.info("Aguardando 25 segundos para propagação DNS…")
            time.sleep(25)

        if args.send or args.full:
            if account is None:
                if not config.account_file.exists():
                    raise VeriscopeError("Conta não existe. Rode --provision primeiro")
                with open(config.account_file) as f:
                    account = json.load(f)

            results = {}
            for email in TARGET_EMAILS:
                code = await send_email(account, email)
                results[email] = code
                time.sleep(4)

            logger.info("=" * 60)
            logger.info("RESUMO FINAL")
            for email, code in results.items():
                status = "SUCESSO" if str(code).startswith("250") else "FALHOU"
                logger.info(f"  {email} → {code} ({status})")
            logger.info("=" * 60)

            with open(config.data_dir / "test_result.json", "w") as f:
                json.dump({
                    "account": account["address"],
                    "results": results,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }, f, indent=2)

        logger.info("Processo concluído.")

    except VeriscopeError as e:
        logger.error(f"ERRO VERISCOPE: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Erro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
