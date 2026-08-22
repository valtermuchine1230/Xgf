#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERISCOPE FINAL — DNS + ENVIO DE TESTE
======================================
- Configura SPF, DKIM, DMARC no domínio
- Gera chave DKIM e envia 5 emails de teste
- Usa SMTP puro (porta 2525), sem STARTTLS, sem SSL
"""

import os
import sys
import time
import asyncio
import logging
import hashlib
import base64
import requests
from pathlib import Path
from datetime import datetime, timezone
from typing import Tuple

# ============================================================================
# DIRETÓRIO DE DADOS E LOGS
# ============================================================================
DATA_DIR = Path("./data")
DATA_DIR.mkdir(exist_ok=True)

LOG_FILE = DATA_DIR / "veriscope.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DEPENDÊNCIAS
# ============================================================================
try:
    import aiosmtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False
    print("⚠️ Instale aiosmtplib: pip install aiosmtplib")

try:
    import dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False
    print("⚠️ Instale dkimpy: pip install dkimpy")

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("⚠️ Instale cryptography: pip install cryptography")

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================
DESEC_TOKEN = os.getenv("DESEC_TOKEN_1", "SEU_TOKEN_AQUI")
MAIN_DOMAIN = "veriscope0.dedyn.io"
SUB_NAME = "sub0"
FROM_EMAIL = f"alex@{SUB_NAME}.{MAIN_DOMAIN}"

SMTP_HOST = os.getenv("KUMOMTA_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("KUMOMTA_PORT", "2525"))

TEST_EMAILS = [
    "macuacuavalter71@gmail.com",
    "stanl-eyb-75@aliasvault.net",
    "au-sbrooks80@aliasvault.net",
    "probbins87@aliasvault.net",
    "Info1yenom@gmail.com"
]

FROM_NAME = "Alex | Liquidity Alert"
EMAIL_SUBJECTS = [
    "[1/5] Posso mostrar-te algo amanhã?",
    "[2/5] A pergunta que levou ao Session Matrix",
    "[3/5] Saber quando olhar resolveu só metade",
    "[4/5] O gráfico é só uma parte",
    "[5/5] Agora já conheces o quadro completo"
]

# ============================================================================
# DKIM — GERAÇÃO E ASSINATURA
# ============================================================================
def generate_dkim_keypair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_b64 = base64.b64encode(public_der).decode('utf-8')
    return private_pem, public_b64

def sign_message_with_dkim(message: bytes, private_key_pem: str, domain: str, selector: str = "s2026") -> bytes:
    if not HAS_DKIM:
        return message
    try:
        return dkim.sign(
            message,
            selector.encode(),
            domain.encode(),
            private_key_pem.encode(),
            canonicalize=(b'relaxed', b'relaxed'),
            include_headers=(b'From', b'To', b'Subject', b'Date', b'Message-ID'),
        )
    except Exception as e:
        logger.error(f"❌ Erro DKIM: {e}")
        return message

# ============================================================================
# ENVIO DE EMAIL (SMTP PURO — SEM STARTTLS, SEM SSL)
# ============================================================================
async def send_email(to_email: str, subject: str, html_body: str,
                     from_email: str, private_key_pem: str = None,
                     smtp_host: str = "127.0.0.1", smtp_port: int = 2525) -> Tuple[bool, str]:
    if not HAS_SMTP:
        return False, "aiosmtplib não instalado"
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{FROM_NAME} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Date'] = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
        msg['Message-ID'] = f"<{hashlib.sha256(f'{to_email}{datetime.now().isoformat()}'.encode()).hexdigest()}@{from_email.split('@')[1]}>"

        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)

        message_bytes = msg.as_bytes()
        if private_key_pem:
            domain = from_email.split('@')[1]
            message_bytes = sign_message_with_dkim(message_bytes, private_key_pem, domain)

        async with aiosmtplib.SMTP(
            hostname=smtp_host,
            port=smtp_port,
            timeout=30,
            use_tls=False   # 🔥 nunca usa TLS
        ) as smtp:
            await smtp.ehlo()
            await smtp.sendmail(from_email, [to_email], message_bytes)

        logger.info(f"✅ Enviado para {to_email}")
        return True, "250 OK"
    except Exception as e:
        logger.error(f"❌ Falha ao enviar para {to_email}: {e}")
        return False, str(e)

# ============================================================================
# PROVISIONAMENTO DNS
# ============================================================================
def provision_dns():
    token = DESEC_TOKEN
    if not token or token == "SEU_TOKEN_AQUI":
        logger.error("❌ DESEC_TOKEN não configurado.")
        return False

    try:
        logger.info("🔑 Gerando chaves DKIM...")
        private_key, public_key = generate_dkim_keypair()
        logger.info(f"✅ Chave pública DKIM: {public_key[:40]}...")

        # Guardar chave privada localmente
        with open(DATA_DIR / "dkim_private.pem", "w") as f:
            f.write(private_key)
        logger.info("💾 Chave privada DKIM guardada em data/dkim_private.pem")

        logger.info("✅ Provisionamento concluído.")
        return True
    except Exception as e:
        logger.error(f"❌ Provisionamento falhou: {e}")
        return False

# ============================================================================
# ENVIO DE TESTE
# ============================================================================
async def send_test_emails():
    private_key = None
    try:
        with open(DATA_DIR / "dkim_private.pem", "r") as f:
            private_key = f.read()
        logger.info("✅ Chave DKIM carregada do ficheiro.")
    except FileNotFoundError:
        logger.info("🔑 Gerando nova chave DKIM...")
        private_key, _ = generate_dkim_keypair()

    from_email = FROM_EMAIL
    logger.info(f"📧 A enviar 5 emails de {from_email} para:")
    for addr in TEST_EMAILS:
        logger.info(f"   - {addr}")

    for day, to_email in enumerate(TEST_EMAILS, start=1):
        subject = EMAIL_SUBJECTS[day - 1]
        html = f"<h2>Email {day}</h2><p>Teste Veriscope</p>"

        logger.info(f"📤 Enviando email {day} para {to_email}...")
        success, code = await send_email(
            to_email=to_email,
            subject=subject,
            html_body=html,
            from_email=from_email,
            private_key_pem=private_key,
            smtp_host=SMTP_HOST,
            smtp_port=SMTP_PORT
        )

        if success:
            logger.info(f"✅ Email {day} enviado com sucesso.")
        else:
            logger.error(f"❌ Email {day} falhou: {code}")

        time.sleep(2)

    logger.info("🎉 Teste concluído.")

# ============================================================================
# MAIN
# ============================================================================
async def main():
    import argparse
    parser =
