#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERISCOPE REAL TEST — 1 DOMÍNIO + 1 SUB-SUBDOMÍNIO REAL
=========================================================
- Cria veriscope0.dedyn.io (se não existir)
- Cria sub0.veriscope0.dedyn.io
- Configura SPF, DKIM, DMARC via API deSEC real
- Envia 5 emails de teste assinados com DKIM
- Usa KumoMTA (ou direct SMTP) para envio

Uso: python veriscope_test_real.py
"""

import os
import sys
import json
import time
import asyncio
import logging
import hashlib
import base64
import requests
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============================================================================
# BIBLIOTECAS OPCIONAIS (verificar importação)
# ============================================================================

try:
    import aiosmtplib
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False
    print("⚠️  aiosmtplib não instalado. Execute: pip install aiosmtplib")

try:
    import dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False
    print("⚠️  dkimpy não instalado. Execute: pip install dkimpy")

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("⚠️  cryptography não instalado. Execute: pip install cryptography")

try:
    from email_validator import validate_email, EmailNotValidError
    HAS_VALIDATOR = True
except ImportError:
    HAS_VALIDATOR = False
    print("⚠️  email-validator não instalado. Execute: pip install email-validator")

# ============================================================================
# CONFIGURAÇÃO — ALTERE AQUI SE NECESSÁRIO
# ============================================================================

# Token deSEC (substituir ou usar variável de ambiente)
DESEC_TOKEN = os.getenv("DESEC_TOKEN_1", "SEU_TOKEN_AQUI")

# Domínio principal e sub-subdomínio
MAIN_DOMAIN = "veriscope0.dedyn.io"
SUB_NAME = "sub0"
FULL_DOMAIN = f"{SUB_NAME}.{MAIN_DOMAIN}"

# IPv6 (se não tiveres, usa um placeholder; o SPF vai funcionar com este IP)
IPV6 = os.getenv("TEST_IPV6", "2a11:6c7:f10:5::1")

# SMTP (KumoMTA ou outro)
SMTP_HOST = os.getenv("KUMOMTA_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("KUMOMTA_PORT", "2525"))

# Emails de teste
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
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ============================================================================
# FUNÇÕES DE API DESEC (REAIS)
# ============================================================================

def call_desec_api(method: str, endpoint: str, token: str, data: dict = None) -> dict:
    """Faz uma chamada à API deSEC com tratamento de erros."""
    url = f"https://desec.io/api/v1/{endpoint}"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    logger.info(f"🌐 {method} {url}")
    response = requests.request(method, url, json=data, headers=headers, timeout=15)
    if response.status_code not in [200, 201, 204]:
        error_msg = f"deSEC API error {response.status_code}: {response.text[:200]}"
        logger.error(error_msg)
        raise Exception(error_msg)
    return response.json() if response.text else {}

def create_domain(domain: str, token: str) -> bool:
    """Cria um domínio principal (ex: veriscope0.dedyn.io)."""
    try:
        # Verificar se já existe
        try:
            call_desec_api("GET", f"domains/{domain}/", token)
            logger.info(f"ℹ️ Domínio {domain} já existe.")
            return True
        except:
            pass
        # Criar
        call_desec_api("POST", "domains/", token, {"name": domain})
        logger.info(f"✅ Domínio {domain} criado com sucesso.")
        return True
    except Exception as e:
        logger.error(f"❌ Falha ao criar domínio {domain}: {e}")
        return False

def create_subdomain(domain: str, sub: str, token: str) -> bool:
    """Cria um sub-subdomínio (ex: sub0.veriscope0.dedyn.io)."""
    full = f"{sub}.{domain}"
    try:
        # Verificar se já existe
        try:
            call_desec_api("GET", f"domains/{full}/", token)
            logger.info(f"ℹ️ Subdomínio {full} já existe.")
            return True
        except:
            pass
        # Criar
        call_desec_api("POST", "domains/", token, {"name": full})
        logger.info(f"✅ Subdomínio {full} criado com sucesso.")
        return True
    except Exception as e:
        logger.error(f"❌ Falha ao criar subdomínio {full}: {e}")
        return False

def configure_spf(domain: str, sub: str, ipv6: str, token: str) -> bool:
    """Configura SPF para o subdomínio."""
    try:
        data = [{
            "subname": sub,
            "type": "TXT",
            "ttl": 3600,
            "records": [f"v=spf1 ip6:{ipv6}/128 -all"]
        }]
        call_desec_api("PUT", f"domains/{domain}/rrsets/", token, data)
        logger.info(f"✅ SPF configurado para {sub}.{domain}")
        return True
    except Exception as e:
        logger.error(f"❌ Falha SPF: {e}")
        return False

def publish_dkim(domain: str, sub: str, public_key_b64: str, token: str) -> bool:
    """Publica a chave pública DKIM no DNS."""
    try:
        selector = f"s2026._domainkey.{sub}"
        data = [{
            "subname": selector,
            "type": "TXT",
            "ttl": 3600,
            "records": [f"v=DKIM1; k=rsa; p={public_key_b64}"]
        }]
        call_desec_api("PUT", f"domains/{domain}/rrsets/", token, data)
        logger.info(f"✅ DKIM publicado para {sub}.{domain}")
        return True
    except Exception as e:
        logger.error(f"❌ Falha DKIM: {e}")
        return False

def configure_dmarc(domain: str, sub: str, token: str) -> bool:
    """Configura DMARC para o subdomínio."""
    try:
        dmarc_sub = f"_dmarc.{sub}"
        data = [{
            "subname": dmarc_sub,
            "type": "TXT",
            "ttl": 3600,
            "records": [f"v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r; rua=mailto:dmarc@{sub}.{domain}"]
        }]
        call_desec_api("PUT", f"domains/{domain}/rrsets/", token, data)
        logger.info(f"✅ DMARC configurado para {sub}.{domain}")
        return True
    except Exception as e:
        logger.error(f"❌ Falha DMARC: {e}")
        return False

# ============================================================================
# DKIM — GERAÇÃO E ASSINATURA
# ============================================================================

def generate_dkim_keypair() -> Tuple[str, str]:
    """Gera par de chaves RSA 2048 para DKIM."""
    if not HAS_CRYPTO:
        raise ImportError("cryptography não instalado")
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
    """Assina uma mensagem com DKIM usando dkimpy."""
    if not HAS_DKIM:
        logger.warning("⚠️ dkimpy não instalado, a enviar sem assinatura.")
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
        logger.error(f"❌ Erro ao assinar DKIM: {e}")
        return message

# ============================================================================
# ENVIO DE EMAIL
# ============================================================================

async def send_email(to_email: str, subject: str, html_body: str,
                     from_email: str, private_key_pem: str = None,
                     smtp_host: str = "127.0.0.1", smtp_port: int = 2525) -> Tuple[bool, str]:
    """Envia email via SMTP (KumoMTA ou directo)."""
    if not HAS_SMTP:
        return False, "aiosmtplib não instalado"

    try:
        # Validar email
        if HAS_VALIDATOR:
            try:
                validate_email(to_email)
            except EmailNotValidError as e:
                logger.warning(f"Email inválido: {to_email} - {e}")
                return False, "400 Invalid email"

        # Construir mensagem
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{FROM_NAME} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Reply-To'] = from_email
        msg['Date'] = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
        msg['Message-ID'] = f"<{hashlib.sha256(f'{to_email}{datetime.now().isoformat()}'.encode()).hexdigest()}@{from_email.split('@')[1]}>"

        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)

        message_bytes = msg.as_bytes()

        # Assinar com DKIM
        if private_key_pem:
            domain = from_email.split('@')[1]
            message_bytes = sign_message_with_dkim(message_bytes, private_key_pem, domain)

        # Enviar via SMTP
        formatted_host = f"[{smtp_host}]" if ':' in smtp_host else smtp_host
        async with aiosmtplib.SMTP(
            hostname=formatted_host,
            port=smtp_port,
            timeout=30,
            use_tls=False
        ) as smtp:
            await smtp.ehlo()
            await smtp.sendmail(from_email, [to_email], message_bytes)

        logger.info(f"✅ Email enviado para {to_email}")
        return True, "250 OK"

    except Exception as e:
        logger.error(f"❌ Erro ao enviar para {to_email}: {e}")
        return False, str(e)

# ============================================================================
# TEMPLATES HTML (5 DIAS, PORTUGUÊS)
# ============================================================================

def get_email_html(day: int) -> str:
    """Devolve o HTML para cada dia."""
    if day == 1:
        return """
        <h2>Posso mostrar-te algo amanhã?</h2>
        <p>Se já estás há alguns anos no trading, provavelmente já viste isto acontecer:</p>
        <p>Um trader perde uma operação e a primeira pergunta que faz é:</p>
        <p><strong>"O que está a faltar no meu gráfico?"</strong></p>
        <p>Depois adiciona mais uma confirmação. Mais um indicador. Mais uma linha.</p>
        <p><strong>E se o problema não for falta de informação?</strong></p>
        <p>Nós começámos a pensar nisso há algum tempo.</p>
        <p><a href="https://veriscope-com-session-matrix.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Ver a ideia</a></p>
        <p>Até amanhã.</p>
        """
    elif day == 2:
        return """
        <h2>A pergunta que levou ao Session Matrix</h2>
        <p>Ontem falei-te de uma pergunta:</p>
        <p><strong>E se o problema não for falta de informação?</strong></p>
        <p>Essa pergunta levou-nos a olhar para o trading de outra forma.</p>
        <p>Muitos traders passam horas à frente do gráfico. Esperam. Analisam.</p>
        <p>Foi daí que nasceu o <strong>Veriscope Session Matrix</strong>.</p>
        <p><a href="https://veriscope-com-session-matrix.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Ver o Session Matrix</a></p>
        """
    elif day == 3:
        return """
        <h2>Saber quando olhar resolveu só metade</h2>
        <p>Quando sabes quando prestar atenção, outra pergunta aparece:</p>
        <p><strong>"O que é que estou realmente a olhar?"</strong></p>
        <p>Foi assim que nasceu o <strong>Veriscope Prime</strong>.</p>
        <p><a href="https://veriscope-com-session-matrix-access.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Ver o Veriscope Prime</a></p>
        """
    elif day == 4:
        return """
        <h2>O gráfico é só uma parte</h2>
        <p>O que acontece à volta de uma operação: risco, tamanho da posição, drawdown, planeamento.</p>
        <p>Foi por isso que criámos o <strong>Veriscope Edge</strong>.</p>
        <p><a href="https://veriscope-com-session-matrix-access.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Conhecer o Veriscope Edge</a></p>
        """
    else:  # day == 5
        return """
        <h2>Agora já conheces o quadro completo</h2>
        <p><strong>Session Matrix</strong> → Quando prestar atenção.</p>
        <p><strong>Prime</strong> → O que estás a olhar.</p>
        <p><strong>Edge</strong> → Como organizas o processo.</p>
        <p>O Veriscope está oficialmente em lançamento.</p>
        <p><a href="https://veriscope-com-prime.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Conhecer o Veriscope</a></p>
        <p>Obrigado por acompanhares estes cinco dias.</p>
        """

def build_full_html(day: int) -> str:
    """Constrói o HTML completo com CSS."""
    content = get_email_html(day)
    logo = """
    <div style="text-align:center;margin-bottom:20px;">
        <svg width="120" height="40" viewBox="0 0 120 40" xmlns="http://www.w3.org/2000/svg">
            <rect width="120" height="40" rx="8" fill="#2563eb"/>
            <circle cx="25" cy="20" r="10" fill="white"/>
            <polygon points="25,28 15,35 35,35" fill="white"/>
            <text x="50" y="27" fill="white" font-size="16" font-weight="bold">Veriscope</text>
        </svg>
    </div>
    """
    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>Email {day}</title></head>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background:#f4f4f4; margin:0; padding:20px;">
        <div style="max-width:600px; margin:0 auto; background:#fff; padding:40px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1);">
            {logo}
            <div style="font-size:16px; line-height:1.8; color:#333;">
                <p>Olá,</p>
                {content}
                <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div style="text-align:center; font-size:12px; color:#999; margin-top:40px; border-top:1px solid #eee; padding-top:20px;">
                <p>&copy; 2026 Veriscope. Todos os direitos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    """

# ============================================================================
# MAIN
# ============================================================================

async def main():
    logger.info("🚀 ===== VERISCOPE REAL TEST — 1 CONTA REAL =====")

    # 0. Verificar token
    token = DESEC_TOKEN
    if not token or token == "SEU_TOKEN_AQUI":
        logger.error("❌ DESEC_TOKEN não configurado. Define a variável de ambiente DESEC_TOKEN_1.")
        sys.exit(1)

    # 1. Criar domínio principal
    logger.info(f"🌐 A criar domínio principal {MAIN_DOMAIN}...")
    if not create_domain(MAIN_DOMAIN, token):
        logger.error("❌ Falha ao criar domínio principal. Abortar.")
        sys.exit(1)

    # 2. Criar sub-subdomínio
    logger.info(f"🌐 A criar sub-subdomínio {FULL_DOMAIN}...")
    if not create_subdomain(MAIN_DOMAIN, SUB_NAME, token):
        logger.error("❌ Falha ao criar sub-subdomínio. Abortar.")
        sys.exit(1)

    # 3. Gerar chaves DKIM
    logger.info("🔑 Gerando chaves DKIM...")
    private_key, public_key = generate_dkim_keypair()
    logger.info(f"✅ Chave pública: {public_key[:40]}...")

    # 4. Configurar SPF
    logger.info("🔧 Configurando SPF...")
    if not configure_spf(MAIN_DOMAIN, SUB_NAME, IPV6, token):
        logger.warning("⚠️ SPF falhou, mas continuando...")

    # 5. Publicar DKIM
    logger.info("🔧 Publicando DKIM...")
    if not publish_dkim(MAIN_DOMAIN, SUB_NAME, public_key, token):
        logger.warning("⚠️ DKIM falhou, mas continuando...")

    # 6. Configurar DMARC
    logger.info("🔧 Configurando DMARC...")
    if not configure_dmarc(MAIN_DOMAIN, SUB_NAME, token):
        logger.warning("⚠️ DMARC falhou, mas continuando...")

    # 7. Enviar emails
    from_email = f"alex@{FULL_DOMAIN}"
    logger.info(f"📧 A enviar 5 emails de {from_email} para:")
    for addr in TEST_EMAILS:
        logger.info(f"   - {addr}")

    for day, to_email in enumerate(TEST_EMAILS, start=1):
        subject = EMAIL_SUBJECTS[day - 1]
        html = build_full_html(day)

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

        time.sleep(2)  # pequena pausa entre envios

    logger.info("🎉 ===== TESTE CONCLUÍDO =====")

if __name__ == "__main__":
    asyncio.run(main())
