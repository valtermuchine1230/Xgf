#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERISCOPE FINAL — PROVISIONAMENTO + TESTE REAL
================================================
- Configura SPF, DKIM, DMARC no domínio veriscope0.dedyn.io
- Gera chave DKIM e envia 5 emails de teste
- Tratamento automático de rate limiting (429) com backoff
- Formato correto para registos TXT (com aspas)
- Suporte a SMTP via KumoMTA (ou outro)

Uso:
  python veriscope_final.py --provision    # só configura DNS
  python veriscope_final.py --send-test    # envia os 5 emails
  python veriscope_final.py --all          # faz tudo
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
from datetime import datetime, timezone
from typing import Tuple

# Dependências opcionais
try:
    import aiosmtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False

try:
    import dkim
    HAS_DKIM = True
except ImportError:
    HAS_DKIM = False

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from email_validator import validate_email, EmailNotValidError
    HAS_VALIDATOR = True
except ImportError:
    HAS_VALIDATOR = False

# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

DESEC_TOKEN = os.getenv("DESEC_TOKEN_1", "SEU_TOKEN_AQUI")
MAIN_DOMAIN = "veriscope0.dedyn.io"
SUB_NAME = "sub0"
FROM_EMAIL = f"alex@{SUB_NAME}.{MAIN_DOMAIN}"

IPV6 = os.getenv("TEST_IPV6", "2a11:6c7:f10:5::1")

# SMTP — usar KumoMTA ou outro
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
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ============================================================================
# FUNÇÕES DA API DESEC (COM RETRY PARA RATE LIMIT)
# ============================================================================

def call_desec_api(method: str, endpoint: str, token: str, data: dict = None, retries: int = 5) -> dict:
    """Faz chamada à API deSEC com retry automático para 429."""
    url = f"https://desec.io/api/v1/{endpoint}"
    headers = {"Authorization": f"Token {token}", "Content-Type": "application/json"}
    
    for attempt in range(1, retries + 1):
        try:
            logger.info(f"🌐 {method} {url} (tentativa {attempt})")
            response = requests.request(method, url, json=data, headers=headers, timeout=15)
            
            if response.status_code == 429:
                wait = int(response.headers.get("Retry-After", 2))
                logger.warning(f"⏳ Rate limit (429). Aguardando {wait}s...")
                time.sleep(wait)
                continue
                
            if response.status_code not in [200, 201, 204]:
                raise Exception(f"deSEC API error {response.status_code}: {response.text[:200]}")
                
            return response.json() if response.text else {}
            
        except Exception as e:
            if attempt == retries:
                raise
            logger.warning(f"⚠️ Erro na tentativa {attempt}: {e}. A repetir...")
            time.sleep(2 ** attempt)  # backoff exponencial

def ensure_domain_exists(domain: str, token: str) -> bool:
    try:
        call_desec_api("GET", f"domains/{domain}/", token)
        logger.info(f"ℹ️ Domínio {domain} já existe.")
        return True
    except:
        try:
            call_desec_api("POST", "domains/", token, {"name": domain})
            logger.info(f"✅ Domínio {domain} criado.")
            return True
        except Exception as e:
            logger.error(f"❌ Falha ao criar domínio: {e}")
            return False

def add_txt_record(domain: str, subname: str, value: str, token: str, ttl: int = 3600) -> bool:
    """
    Adiciona um registo TXT no formato correto (com aspas).
    Exemplo: value = "v=spf1 ip6:... -all"  →  o API espera ["\"v=spf1 ...\""]
    """
    # A API deSEC exige que cada registo seja uma string com aspas duplas internas
    quoted = f'"{value}"'
    data = [{
        "subname": subname,
        "type": "TXT",
        "ttl": ttl,
        "records": [quoted]
    }]
    try:
        call_desec_api("PUT", f"domains/{domain}/rrsets/", token, data)
        logger.info(f"✅ TXT {subname} configurado.")
        return True
    except Exception as e:
        logger.error(f"❌ Falha TXT {subname}: {e}")
        return False

# ============================================================================
# DKIM — GERAÇÃO E ASSINATURA
# ============================================================================

def generate_dkim_keypair() -> Tuple[str, str]:
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
        logger.error(f"❌ Erro DKIM: {e}")
        return message

# ============================================================================
# ENVIO DE EMAIL
# ============================================================================

async def send_email(to_email: str, subject: str, html_body: str,
                     from_email: str, private_key_pem: str = None,
                     smtp_host: str = "127.0.0.1", smtp_port: int = 2525) -> Tuple[bool, str]:
    if not HAS_SMTP:
        return False, "aiosmtplib não instalado"
    try:
        if HAS_VALIDATOR:
            try:
                validate_email(to_email)
            except EmailNotValidError as e:
                logger.warning(f"Email inválido: {to_email} - {e}")
                return False, "400 Invalid email"

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
        if private_key_pem:
            domain = from_email.split('@')[1]
            message_bytes = sign_message_with_dkim(message_bytes, private_key_pem, domain)

        # Tentar ligar ao SMTP
        formatted_host = f"[{smtp_host}]" if ':' in smtp_host else smtp_host
        async with aiosmtplib.SMTP(
            hostname=formatted_host,
            port=smtp_port,
            timeout=30,
            use_tls=False  # KumoMTA geralmente não usa TLS na porta 2525
        ) as smtp:
            await smtp.ehlo()
            await smtp.sendmail(from_email, [to_email], message_bytes)

        logger.info(f"✅ Enviado para {to_email}")
        return True, "250 OK"
    except Exception as e:
        logger.error(f"❌ Falha ao enviar para {to_email}: {e}")
        return False, str(e)

# ============================================================================
# TEMPLATES HTML (5 DIAS)
# ============================================================================

def get_email_html(day: int) -> str:
    if day == 1:
        return """
        <h2>Posso mostrar-te algo amanhã?</h2>
        <p>Se já estás há alguns anos no trading, provavelmente já viste isto acontecer:</p>
        <p>Um trader perde uma operação e a primeira pergunta que faz é:</p>
        <p><strong>"O que está a faltar no meu gráfico?"</strong></p>
        <p><strong>E se o problema não for falta de informação?</strong></p>
        <p><a href="https://veriscope-com-session-matrix.pages.dev/" style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;">Ver a ideia</a></p>
        """
    elif day == 2:
        return """
        <h2>A pergunta que levou ao Session Matrix</h2>
        <p>Ontem falei-te de uma pergunta:</p>
        <p><strong>E se o problema não for falta de informação?</strong></p>
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
    else:
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
# PROVISIONAMENTO
# ============================================================================

def provision_dns():
    """Configura SPF, DKIM, DMARC no DNS."""
    token = DESEC_TOKEN
    if not token or token == "SEU_TOKEN_AQUI":
        logger.error("❌ DESEC_TOKEN não configurado.")
        return False

    # 1. Garantir domínio principal
    if not ensure_domain_exists(MAIN_DOMAIN, token):
        return False

    # 2. Gerar chave DKIM
    logger.info("🔑 Gerando chaves DKIM...")
    private_key, public_key = generate_dkim_keypair()
    logger.info(f"✅ Chave pública: {public_key[:40]}...")

    # 3. SPF
    logger.info("🔧 Configurando SPF...")
    spf_value = f"v=spf1 ip6:{IPV6}/128 -all"
    if not add_txt_record(MAIN_DOMAIN, SUB_NAME, spf_value, token):
        logger.warning("⚠️ SPF falhou, mas continuando...")

    # 4. DKIM
    logger.info("🔧 Publicando DKIM...")
    dkim_sub = f"s2026._domainkey.{SUB_NAME}"
    dkim_value = f"v=DKIM1; k=rsa; p={public_key}"
    if not add_txt_record(MAIN_DOMAIN, dkim_sub, dkim_value, token):
        logger.warning("⚠️ DKIM falhou, mas continuando...")

    # 5. DMARC
    logger.info("🔧 Configurando DMARC...")
    dmarc_sub = f"_dmarc.{SUB_NAME}"
    dmarc_value = f"v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r; rua=mailto:dmarc@{SUB_NAME}.{MAIN_DOMAIN}"
    if not add_txt_record(MAIN_DOMAIN, dmarc_sub, dmarc_value, token):
        logger.warning("⚠️ DMARC falhou, mas continuando...")

    logger.info("✅ Provisionamento concluído.")
    return True

# ============================================================================
# ENVIO DE TESTE
# ============================================================================

async def send_test_emails():
    """Envia 5 emails de teste."""
    # Regenerar chave DKIM (ou carregar de ficheiro)
    logger.info("🔑 Gerando chave DKIM para assinatura...")
    private_key, _ = generate_dkim_keypair()

    from_email = FROM_EMAIL
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

        time.sleep(2)  # pausa entre emails

    logger.info("🎉 Teste concluído.")

# ============================================================================
# MAIN
# ============================================================================

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Veriscope Final — DNS + Teste")
    parser.add_argument("--provision", action="store_true", help="Apenas configurar DNS")
    parser.add_argument("--send-test", action="store_true", help="Apenas enviar emails")
    parser.add_argument("--all", action="store_true", help="Faz tudo (provision + send-test)")
    args = parser.parse_args()

    if not any([args.provision, args.send_test, args.all]):
        parser.print_help()
        return

    if args.provision or args.all:
        logger.info("🚀 A executar provisionamento DNS...")
        if not provision_dns():
            logger.error("❌ Provisionamento falhou.")
            if not args.all:
                return

    if args.send_test or args.all:
        logger.info("🚀 A enviar emails de teste...")
        await send_test_emails()

if __name__ == "__main__":
    asyncio.run(main())
