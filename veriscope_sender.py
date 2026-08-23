#!/usr/bin/env python3
"""
Veriscope SMTP Engine – Versão Debug Completa
Logs extremamente detalhados para identificar qualquer travamento.
"""

from __future__ import annotations
import os
import sys
import json
import time
import logging
import argparse
import traceback
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
# Logging extremamente detalhado
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("veriscope.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("veriscope")

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
DOMAIN = "veriscope0.dedyn.io"
SUB = "sub001"
FULL_DOMAIN = f"{SUB}.{DOMAIN}"
EMAIL_ADDRESS = f"alex@{FULL_DOMAIN}"
SELECTOR = "s2026"

# IPv6 do bloco real que aparece no painel Route64 (/56)
IPV6 = "2a11:6c7:2600:de00::10"

TARGET_EMAILS = [
    "Macuacuavalter71@gmail.com",
    "Info1yenom@gmail.com",
]

class Config:
    def __init__(self):
        logger.info(">>> Iniciando Config.__init__")
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

        logger.info(f"HF_REPO = {self.hf_repo}")
        logger.info(f"Route64 URL = {self.route64_url}")
        logger.info(f"KumoMTA = {self.kumomta_host}:{self.kumomta_port}")
        logger.info(f"IPv6 = {IPV6}")
        logger.info(f"Tokens deSEC encontrados = {len(self.desec_tokens)}")

        self._validate()
        logger.info(">>> Config carregada com sucesso")

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

config = Config()

class VeriscopeError(Exception):
    def __init__(self, message: str, **ctx):
        super().__init__(f"{message} | {ctx}" if ctx else message)

# ---------------------------------------------------------------------------
# deSEC
# ---------------------------------------------------------------------------
class DesecClient:
    BASE = "https://desec.io/api/v1"

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.idx = 0
        self.session = requests.Session()
        self.last = 0.0
        logger.debug("DesecClient inicializado")

    def _token(self):
        t = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return t

    def _req(self, method, path, **kw):
        elapsed = time.time() - self.last
        if elapsed < 1.0:
            sleep_time = 1.0 - elapsed
            logger.debug(f"deSEC rate-limit sleep {sleep_time:.2f}s")
            time.sleep(sleep_time)

        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Token {self._token()}"
        headers.setdefault("Content-Type", "application/json")
        url = f"{self.BASE}{path}"

        logger.info(f"deSEC REQUEST → {method} {url}")
        try:
            r = self.session.request(method, url, headers=headers, timeout=45, **kw)
            self.last = time.time()
            logger.info(f"deSEC RESPONSE → status={r.status_code}")

            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 60))
                logger.warning(f"deSEC 429 → esperando {wait}s")
                time.sleep(wait + 2)
                return self._req(method, path, **kw)
            return r
        except requests.RequestException as e:
            logger.error(f"deSEC EXCEPTION: {e}")
            raise VeriscopeError("Falha de rede deSEC", error=str(e))

    def create_rrsets(self, rrsets: List[Dict]):
        logger.info(f">>> deSEC create_rrsets ({len(rrsets)} registos)")
        r = self._req("PUT", f"/domains/{DOMAIN}/rrsets/", json=rrsets)
        if r.status_code not in (200, 201, 204):
            logger.error(f"deSEC body: {r.text[:800]}")
            raise VeriscopeError("deSEC falhou", status=r.status_code, body=r.text[:500])
        logger.info(">>> deSEC RRsets publicados com sucesso")

# ---------------------------------------------------------------------------
# Route64
# ---------------------------------------------------------------------------
class Route64Client:
    def __init__(self, key: str, base: str):
        self.key = key
        self.base = base
        self.s = requests.Session()
        logger.debug(f"Route64Client inicializado → {base}")

    def create_ptr(self, ipv6: str, hostname: str) -> bool:
        logger.info(f">>> Route64 create_ptr {ipv6} → {hostname}")
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        try:
            logger.debug("Tentativa POST /rdns/create/")
            r = self.s.post(
                f"{self.base}/rdns/create/",
                headers=headers,
                json={"ip": ipv6, "hostname": hostname},
                timeout=20,
            )
            logger.info(f"Route64 POST status={r.status_code}")
            if r.status_code in (200, 201):
                logger.info(">>> Route64 PTR criado com sucesso")
                return True

            logger.debug("Tentativa PUT /rdns/<ip>/")
            r = self.s.put(
                f"{self.base}/rdns/{ipv6}/",
                headers=headers,
                json={"hostname": hostname},
                timeout=20,
            )
            logger.info(f"Route64 PUT status={r.status_code}")
            if r.status_code in (200, 201):
                logger.info(">>> Route64 PTR criado com sucesso (PUT)")
                return True

            logger.warning(f"Route64 PTR falhou (status {r.status_code}): {r.text[:400]}")
            return False
        except Exception as e:
            logger.warning(f"Route64 PTR EXCEPTION: {e}")
            return False

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------
class DKIMManager:
    @staticmethod
    def generate() -> Tuple[str, str]:
        logger.info(">>> Gerando chave DKIM 2048-bit…")
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
        logger.info(">>> Chave DKIM gerada")
        return priv_pem, "".join(lines)

    @staticmethod
    def sign(msg: bytes, domain: str, selector: str, priv_pem: str) -> bytes:
        logger.debug(f"Assinando DKIM domain={domain} selector={selector}")
        return dkim.sign(
            msg,
            selector.encode(),
            domain.encode(),
            priv_pem.encode(),
            include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
            canonicalize=(b"relaxed", b"relaxed"),
        )

# ---------------------------------------------------------------------------
# Criar conta
# ---------------------------------------------------------------------------
def create_account() -> Dict:
    logger.info("=" * 60)
    logger.info(">>> INÍCIO create_account()")
    logger.info(f"Endereço: {EMAIL_ADDRESS}")
    logger.info(f"IPv6: {IPV6}")

    desec = DesecClient(config.desec_tokens)
    route64 = Route64Client(config.route64_key, config.route64_url)

    priv_pem, pub_b64 = DKIMManager.generate()

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

    logger.info(">>> Chamando deSEC…")
    desec.create_rrsets(rrsets)

    logger.info(">>> Chamando Route64 PTR…")
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

    logger.info(">>> Gravando account.json localmente…")
    with open(config.account_file, "w") as f:
        json.dump(account, f, indent=2)
    logger.info(">>> account.json gravado")

    # Upload HF com timeout e nunca bloqueia
    logger.info(">>> Tentando upload HuggingFace (timeout 30s)…")
    try:
        api = HfApi(token=config.hf_token)
        api.upload_file(
            path_or_fileobj=str(config.account_file),
            path_in_repo="accounts/email_0001.json",
            repo_id=config.hf_repo,
            repo_type="dataset",
            commit_message="Conta alex@sub001.veriscope0.dedyn.io",
        )
        logger.info(">>> Upload HuggingFace OK")
    except Exception as e:
        logger.warning(f"Upload HF falhou (não crítico): {e}")

    logger.info(f">>> Conta criada com sucesso: {EMAIL_ADDRESS}")
    logger.info("=" * 60)
    return account

# ---------------------------------------------------------------------------
# Enviar e-mail
# ---------------------------------------------------------------------------
async def send_email(account: Dict, to_addr: str) -> str:
    logger.info(f">>> INÍCIO send_email → {to_addr}")

    subject = f"Veriscope – Teste ({datetime.now().strftime('%H:%M:%S')})"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0;padding:0;background:#0a0a0a;font-family:Arial,sans-serif;">
      <table width="100%" style="background:#0a0a0a;padding:40px 0;">
        <tr><td align="center">
          <table width="560" style="background:#111;border-radius:12px;border:1px solid #2a2a2a;">
            <tr>
              <td style="padding:32px 40px;text-align:center;border-bottom:1px solid #222;">
                <div style="font-size:28px;color:#C9A567;">◆</div>
                <div style="margin-top:10px;color:#F5F5F3;font-size:22px;font-weight:700;letter-spacing:6px;">VERISCOPE</div>
              </td>
            </tr>
            <tr>
              <td style="padding:36px 40px;color:#e0e0e0;font-size:15px;line-height:1.7;">
                <p style="color:#C9A567;font-size:13px;text-transform:uppercase;">Teste de Deliverability</p>
                <h2 style="color:#fff;margin:10px 0 20px;">Sistema operacional</h2>
                <p>Conta: <strong>{account['address']}</strong></p>
                <p>IPv6: <code>{account['ipv6']}</code></p>
                <p>Hora UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</p>
              </td>
            </tr>
          </table>
        </td></tr>
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
    logger.debug("Assinando mensagem com DKIM…")
    signed = DKIMManager.sign(
        raw,
        domain=account["domain"],
        selector=account["dkim_selector"],
        priv_pem=account["dkim_private_pem"],
    )
    logger.debug(f"Mensagem assinada ({len(signed)} bytes)")

    try:
        logger.info(f"Ligando ao KumoMTA {config.kumomta_host}:{config.kumomta_port}…")
        smtp = aiosmtplib.SMTP(
            hostname=config.kumomta_host,
            port=config.kumomta_port,
            timeout=30,
            use_tls=False,
            start_tls=False,
            validate_certs=False,
        )
        await smtp.connect()
        logger.info("Ligado ao KumoMTA. A enviar…")
        await smtp.sendmail(account["address"], [to_addr], signed)
        await smtp.quit()
        logger.info(f"✓ Enviado com sucesso → {to_addr}")
        return "250 OK"
    except aiosmtplib.SMTPResponseException as e:
        logger.error(f"SMTP {e.code} → {to_addr}: {e.message}")
        return f"{e.code} {e.message}"
    except Exception as e:
        logger.error(f"Falha SMTP: {e}")
        logger.error(traceback.format_exc())
        raise VeriscopeError("Falha SMTP", to=to_addr, error=str(e))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    logger.info("=" * 60)
    logger.info("VERISCOPE SENDER – INÍCIO")
    logger.info("=" * 60)

    parser = argparse.ArgumentParser()
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--send", action="store_true")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()

    if not any([args.provision, args.send, args.full]):
        parser.print_help()
        sys.exit(0)

    try:
        account = None

        if args.provision or args.full:
            logger.info(">>> Modo PROVISION / FULL – a criar conta…")
            account = create_account()
            logger.info(">>> Aguardando 20 segundos para propagação DNS…")
            time.sleep(20)
            logger.info(">>> Fim da espera de propagação")

        if args.send or args.full:
            logger.info(">>> Modo SEND / FULL – a enviar e-mails…")
            if account is None:
                if not config.account_file.exists():
                    raise VeriscopeError("Conta não existe. Rode --provision primeiro")
                logger.info(">>> A carregar account.json…")
                with open(config.account_file) as f:
                    account = json.load(f)
                logger.info(f">>> Conta carregada: {account['address']}")

            results = {}
            for i, email in enumerate(TARGET_EMAILS, 1):
                logger.info(f">>> Envio {i}/{len(TARGET_EMAILS)}")
                code = await send_email(account, email)
                results[email] = code
                logger.info(f">>> Resultado {email}: {code}")
                time.sleep(3)

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

        logger.info(">>> PROCESSO CONCLUÍDO COM SUCESSO")

    except VeriscopeError as e:
        logger.error(f"ERRO VERISCOPE: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"ERRO INESPERADO: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
