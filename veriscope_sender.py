#!/usr/bin/env python3
"""
Veriscope SMTP Engine – Versão de Teste Completa
Cria 1 conta real (sub-subdomínio + SPF + DKIM + DMARC + PTR)
Envia e-mails reais para:
  - Macuacuavalter71@gmail.com
  - Info1yenom@gmail.com

Repositório de estado: Valter3B/veriscope_checkpoints
"""

from __future__ import annotations
import os
import sys
import json
import time
import hashlib
import logging
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

import requests
from tenacity import retry, stop_after_attempt, wait_exponential
from huggingface_hub import HfApi
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import dkim
import aiosmtplib
import asyncio

# ---------------------------------------------------------------------------
# Logging detalhado
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
# Configuração
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN")
        self.hf_repo = os.getenv("HF_REPO", "Valter3B/veriscope_checkpoints")
        self.desec_domain = os.getenv("DESEC_DOMAIN")
        self.desec_tokens = [
            os.getenv(f"DESEC_TOKEN_{i}")
            for i in range(1, 27)
            if os.getenv(f"DESEC_TOKEN_{i}")
        ]
        self.route64_key = os.getenv("ROUTE64_API_KEY")
        self.route64_url = os.getenv("ROUTE64_API_URL", "https://manager.route64.org/api").rstrip("/")
        self.route64_block = os.getenv("ROUTE64_IPV6_BLOCK", "2a11:6c7:f10:5::/64")
        self.kumomta_host = os.getenv("KUMOMTA_HOST", "127.0.0.1")
        self.kumomta_port = int(os.getenv("KUMOMTA_PORT", "2525"))
        self.from_name = os.getenv("KUMOMTA_FROM_NAME", "Alex | Liquidity Alert")

        # E-mails de teste hardcoded (como pediste)
        self.target_emails = [
            "Macuacuavalter71@gmail.com",
            "Info1yenom@gmail.com",
        ]

        self.data_dir = Path("data")
        self.data_dir.mkdir(exist_ok=True)

        self._validate()

    def _validate(self):
        missing = []
        if not self.hf_token:
            missing.append("HF_TOKEN")
        if not self.desec_domain:
            missing.append("DESEC_DOMAIN")
        if not self.desec_tokens:
            missing.append("DESEC_TOKEN_1..26")
        if not self.route64_key:
            missing.append("ROUTE64_API_KEY")

        if missing:
            msg = (
                f"FALHA CRÍTICA DE CONFIGURAÇÃO\n"
                f"Variáveis em falta: {', '.join(missing)}\n"
                f"Verifique os GitHub Secrets e tente novamente."
            )
            logger.error(msg)
            raise SystemExit(1)

        logger.info(
            f"Configuração OK | domínio={self.desec_domain} | "
            f"tokens deSEC={len(self.desec_tokens)} | "
            f"destinatários={len(self.target_emails)}"
        )

config = Config()

# ---------------------------------------------------------------------------
# Erro detalhado
# ---------------------------------------------------------------------------
class VeriscopeError(Exception):
    def __init__(self, message: str, **context):
        self.context = context
        full = f"{message}"
        if context:
            full += " | " + " | ".join(f"{k}={v}" for k, v in context.items())
        super().__init__(full)

# ---------------------------------------------------------------------------
# deSEC Client
# ---------------------------------------------------------------------------
class DesecClient:
    BASE = "https://desec.io/api/v1"

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.idx = 0
        self.session = requests.Session()
        self.last_call = 0.0

    def _token(self) -> str:
        t = self.tokens[self.idx % len(self.tokens)]
        self.idx += 1
        return t

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        # Rate limit conservador
        elapsed = time.time() - self.last_call
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Token {self._token()}"
        headers.setdefault("Content-Type", "application/json")

        url = f"{self.BASE}{path}"
        try:
            resp = self.session.request(method, url, headers=headers, timeout=30, **kwargs)
            self.last_call = time.time()

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 60))
                logger.warning(f"deSEC 429 Too Many Requests → aguardando {wait}s")
                time.sleep(wait + 2)
                return self._request(method, path, **kwargs)

            return resp
        except requests.RequestException as e:
            raise VeriscopeError("Falha de rede na deSEC", error=str(e), path=path)

    def create_rrsets(self, domain: str, rrsets: List[Dict]) -> None:
        logger.info(f"deSEC → criando {len(rrsets)} RRsets em {domain}…")
        resp = self._request("PUT", f"/domains/{domain}/rrsets/", json=rrsets)

        if resp.status_code not in (200, 201, 204):
            raise VeriscopeError(
                "deSEC falhou ao criar RRsets",
                status=resp.status_code,
                body=resp.text[:600],
                domain=domain,
            )
        logger.info("deSEC → RRsets criados com sucesso")

# ---------------------------------------------------------------------------
# Route64 Client
# ---------------------------------------------------------------------------
class Route64Client:
    def __init__(self, key: str, base: str):
        self.key = key
        self.base = base
        self.session = requests.Session()

    def create_ptr(self, ipv6: str, hostname: str) -> None:
        logger.info(f"Route64 → criando PTR {ipv6} → {hostname}")
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        payload = {"ip": ipv6, "hostname": hostname}

        # Tenta create
        resp = self.session.post(
            f"{self.base}/rdns/create/",
            headers=headers,
            json=payload,
            timeout=25,
        )

        if resp.status_code not in (200, 201):
            # Fallback PUT
            resp = self.session.put(
                f"{self.base}/rdns/{ipv6}/",
                headers=headers,
                json={"hostname": hostname},
                timeout=25,
            )

        if resp.status_code not in (200, 201):
            raise VeriscopeError(
                "Route64 falhou ao criar PTR",
                status=resp.status_code,
                body=resp.text[:400],
                ipv6=ipv6,
                hostname=hostname,
            )
        logger.info("Route64 → PTR criado com sucesso")

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------
class DKIMManager:
    @staticmethod
    def generate() -> Tuple[str, str]:
        private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        pub = private.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        # Remover cabeçalhos PEM
        lines = [l for l in pub_pem.splitlines() if not l.startswith("-----")]
        pub_b64 = "".join(lines)
        return priv_pem, pub_b64

    @staticmethod
    def sign(message: bytes, domain: str, selector: str, private_pem: str) -> bytes:
        try:
            return dkim.sign(
                message,
                selector.encode(),
                domain.encode(),
                private_pem.encode(),
                include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
                canonicalize=(b"relaxed", b"relaxed"),
            )
        except Exception as e:
            raise VeriscopeError(
                "Falha na assinatura DKIM",
                domain=domain,
                selector=selector,
                error=str(e),
            )

# ---------------------------------------------------------------------------
# Criação da conta única
# ---------------------------------------------------------------------------
def create_one_account() -> Dict:
    logger.info("=== CRIANDO 1 CONTA SMTP REAL ===")

    desec = DesecClient(config.desec_tokens)
    route64 = Route64Client(config.route64_key, config.route64_url)

    # Nome do sub-subdomínio
    sub = "mail01"
    full_domain = f"{sub}.{config.desec_domain}"
    address = f"alex@{full_domain}"
    selector = "s2026"

    # Gerar chave DKIM
    priv_pem, pub_b64 = DKIMManager.generate()
    logger.info("Chave DKIM 2048-bit gerada")

    # IPv6 dentro do bloco Route64
    # Usamos um endereço fixo e previsível para este teste
    ipv6 = "2a11:6c7:f10:5::10"

    # RRsets
    rrsets = [
        {
            "subname": sub,
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"v=spf1 ip6:{ipv6}/128 -all"'],
        },
        {
            "subname": f"{selector}._domainkey.{sub}",
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"v=DKIM1; k=rsa; p={pub_b64}"'],
        },
        {
            "subname": f"_dmarc.{sub}",
            "type": "TXT",
            "ttl": 3600,
            "records": ['"v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r"'],
        },
        {
            "subname": sub,
            "type": "AAAA",
            "ttl": 3600,
            "records": [ipv6],
        },
    ]

    # Publicar no deSEC
    desec.create_rrsets(config.desec_domain, rrsets)

    # PTR no Route64
    try:
        route64.create_ptr(ipv6, full_domain)
    except VeriscopeError as e:
        logger.warning(f"PTR Route64 falhou (continua mesmo assim): {e}")

    account = {
        "id": "email_0001",
        "address": address,
        "domain": full_domain,
        "ipv6": ipv6,
        "dkim_selector": selector,
        "dkim_private_pem": priv_pem,
        "dkim_public_b64": pub_b64,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Guardar localmente
    with open(config.data_dir / "account.json", "w") as f:
        json.dump(account, f, indent=2)

    # Upload para HuggingFace
    try:
        api = HfApi(token=config.hf_token)
        api.upload_file(
            path_or_fileobj=str(config.data_dir / "account.json"),
            path_in_repo="accounts/email_0001.json",
            repo_id=config.hf_repo,
            repo_type="dataset",
            commit_message="Conta de teste email_0001 criada",
        )
        logger.info("Conta enviada para HuggingFace")
    except Exception as e:
        logger.warning(f"Upload HF falhou (não crítico): {e}")

    logger.info(f"Conta criada com sucesso → {address}")
    return account

# ---------------------------------------------------------------------------
# Envio de e-mail
# ---------------------------------------------------------------------------
async def send_one_email(account: Dict, to_addr: str) -> str:
    logger.info(f"Enviando para {to_addr}…")

    subject = f"[Veriscope Teste] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <h2>Teste de Deliverability – Veriscope</h2>
      <p>Olá,</p>
      <p>Este é um e-mail de teste enviado pelo sistema Veriscope.</p>
      <p>
        Conta de envio: <strong>{account['address']}</strong><br>
        IPv6: <code>{account['ipv6']}</code><br>
        Hora: {datetime.now(timezone.utc).isoformat()}
      </p>
      <p>Se recebeste este e-mail na caixa de entrada (não no spam), a autenticação está a funcionar.</p>
      <hr>
      <p style="font-size: 12px; color: #888;">
        Alex | Liquidity Alert<br>
        Teste automático – pode ignorar.
      </p>
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

    # Assinar com DKIM
    signed = DKIMManager.sign(
        raw,
        domain=account["domain"],
        selector=account["dkim_selector"],
        private_pem=account["dkim_private_pem"],
    )

    try:
        smtp = aiosmtplib.SMTP(
            hostname=config.kumomta_host,
            port=config.kumomta_port,
            timeout=40,
        )
        await smtp.connect()
        await smtp.sendmail(account["address"], [to_addr], signed)
        await smtp.quit()
        logger.info(f"✓ Enviado com sucesso para {to_addr}")
        return "250 OK"
    except aiosmtplib.SMTPResponseException as e:
        logger.error(f"SMTP {e.code} para {to_addr}: {e.message}")
        return f"{e.code} {e.message}"
    except Exception as e:
        raise VeriscopeError("Falha inesperada no envio SMTP", to=to_addr, error=str(e))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    logger.info("=" * 60)
    logger.info("VERISCOPE – TESTE COMPLETO (1 conta → 2 emails)")
    logger.info("=" * 60)

    try:
        # 1. Criar a conta
        account = create_one_account()

        # 2. Aguardar um pouco para propagação DNS (opcional mas recomendado)
        logger.info("Aguardando 15 segundos para propagação DNS…")
        time.sleep(15)

        # 3. Enviar para os dois e-mails
        results = {}
        for email in config.target_emails:
            code = await send_one_email(account, email)
            results[email] = code
            time.sleep(3)  # Pequeno intervalo

        # 4. Resumo final
        logger.info("=" * 60)
        logger.info("RESUMO DO TESTE")
        for email, code in results.items():
            status = "SUCESSO" if code.startswith("250") else "FALHOU"
            logger.info(f"  {email} → {code} ({status})")
        logger.info("=" * 60)

        # Guardar resultado
        with open(config.data_dir / "test_result.json", "w") as f:
            json.dump(
                {
                    "account": account["address"],
                    "results": results,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                f,
                indent=2,
            )

        logger.info("Teste concluído. Verifique as caixas de entrada (e a pasta de spam).")

    except VeriscopeError as e:
        logger.error(f"ERRO VERISCOPE: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Erro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
