#!/usr/bin/env python3
"""
Envio de emails de teste via KumoMTA - VERSÃO CORRIGIDA
"""

import os
import json
import logging
import smtplib
import hashlib
import email.utils
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from huggingface_hub import hf_hub_download
from dkimpy import sign

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

HF_TOKEN = os.getenv("HF_TOKEN")
HF_REPO = os.getenv("HF_REPO", "veriscope/checkpoints")

TEST_RECIPIENTS = [
    "macuacuavalter71@gmail.com",
    "Info1yenom@gmail.com"
]

# ⚠️ TEMPLATE CORRIGIDA - {{ }} escapado para {{{{ }}}}
EMAIL_TEMPLATE_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Veriscope — Session Matrix</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }}
    .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
    .header {{ background: linear-gradient(135deg, #1a3a52 0%, #2d5a7a 100%); padding: 40px 20px; text-align: center; }}
    .logo {{ font-size: 28px; font-weight: bold; color: #c9a961; margin-bottom: 10px; }}
    .content {{ padding: 40px 30px; line-height: 1.6; color: #333; }}
    .content h2 {{ font-size: 20px; margin: 0 0 20px 0; color: #1a3a52; }}
    .content p {{ margin: 15px 0; font-size: 15px; }}
    .cta-button {{ display: inline-block; background: #c9a961; color: #1a3a52; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 25px 0; }}
    .cta-button:hover {{ background: #b39351; }}
    .footer {{ background: #f9f9f9; padding: 20px 30px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #eee; }}
    .footer a {{ color: #c9a961; text-decoration: none; }}
    .signature {{ margin-top: 20px; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">⬥ VERISCOPE</div>
      <div style="font-size: 14px; color: #c9a961; margin-top: 10px;">Insight | Decision | Execution</div>
    </div>
    
    <div class="content">
      <h2>[{email_number}/5] Posso mostrar-te algo amanhã?</h2>
      
      <p>Olá,</p>
      
      <p>Se já estás há alguns anos no trading, provavelmente já viste isto acontecer:</p>
      
      <p>Um trader perde uma operação e a primeira pergunta que faz é:</p>
      
      <p><strong>"O que está a faltar no meu gráfico?"</strong></p>
      
      <p>Depois adiciona mais uma confirmação. Mais um indicador. Mais uma linha.</p>
      
      <p>Mas existe uma pergunta que quase ninguém faz:</p>
      
      <p><strong>E se o problema não for falta de informação?</strong></p>
      
      <p>Nós começámos a pensar nisso há algum tempo.</p>
      
      <p>Amanhã vou mostrar-te uma ferramenta que nasceu precisamente de uma pergunta que talvez tu próprio já tenhas feito.</p>
      
      <p>Chama-se <strong>Veriscope Session Matrix</strong>.</p>
      
      <div style="text-align: center; margin: 30px 0;">
        <a href="https://veriscope-com-session-matrix.pages.dev/?utm_source=email&utm_campaign=launch&hash={tracking_hash}" class="cta-button">Ver a ideia →</a>
      </div>
      
      <p>Amanhã, à mesma hora, envio-te o próximo e-mail.</p>
      
      <p style="margin-bottom: 30px;">Sem custos. Sem cartão. Sem conta.</p>
      
      <div class="signature">
        <p style="margin: 10px 0;">Alex</p>
        <p style="margin: 0; color: #c9a961;">Liquidity Alert</p>
      </div>
    </div>
    
    <div class="footer">
      <p>© 2026 Veriscope. Todos os direitos reservados.</p>
      <p><a href="https://veriscope.com/unsubscribe?email={recipient_email}">Cancelar inscrição</a></p>
      <img src="https://tracking.veriscope.com/pixel?lead={recipient_email}&email=1&hash={tracking_hash}" width="1" height="1" style="display:none;" alt="">
    </div>
  </div>
</body>
</html>"""

def load_account_from_hf():
    """Carrega dados da conta do HuggingFace"""
    logger.info(f"Carregando conta do HF ({HF_REPO})...")
    
    if not HF_TOKEN:
        raise ValueError("HF_TOKEN não configurado")
    
    try:
        file_path = hf_hub_download(
            repo_id=HF_REPO,
            filename="sender_account.json",
            repo_type="dataset",
            token=HF_TOKEN
        )
        
        with open(file_path, "r") as f:
            account = json.load(f)
        
        logger.info(f"✓ Conta carregada: {account['address']}")
        return account
        
    except Exception as e:
        logger.error(f"✗ Erro ao carregar conta do HF: {e}")
        raise

def generate_tracking_hash(email, recipient):
    """Gera hash único para rastreamento"""
    unique_str = f"{email}:{recipient}:{datetime.utcnow().isoformat()}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

def apply_mutation(html_content, tracking_hash, recipient_email, email_num):
    """Aplica mutação ao HTML"""
    logger.info(f"  → Aplicando mutação para {recipient_email}...")
    
    # Substituir placeholders
    content = html_content.format(
        tracking_hash=tracking_hash,
        recipient_email=recipient_email,
        email_number=email_num
    )
    
    # Adicionar elemento DOM invisível
    rnd_class = f"rnd_{tracking_hash[:8]}"
    invisible_div = f'<div style="display:none;" class="{rnd_class}"><!-- {tracking_hash} --></div>'
    content = content.replace("</body>", f"{invisible_div}</body>")
    
    return content

def sign_email_with_dkim(message, account):
    """Assina email com DKIM"""
    logger.info("  → Assinando com DKIM...")
    
    domain = account['full_domain'].encode('utf-8')
    selector = account['dkim_selector'].encode('utf-8')
    private_key = account['dkim_private_key'].encode('utf-8')
    
    headers_to_sign = [b'from', b'to', b'subject', b'date']
    
    try:
        sig = sign(
            message.as_bytes(),
            selector,
            domain,
            private_key,
            include_headers=headers_to_sign
        )
        
        signed_message = sig + message.as_bytes()
        
        logger.info("  ✓ DKIM assinado")
        return signed_message
        
    except Exception as e:
        logger.warning(f"  ✗ Erro ao assinar DKIM: {e}")
        return message.as_bytes()

def send_email_via_smtp(account, recipient, tracking_hash, email_num=1):
    """Envia email via KumoMTA"""
    logger.info(f"Enviando para {recipient}...")
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{account['sender_name']} <{account['address']}>"
        msg['To'] = recipient
        msg['Subject'] = f"[{email_num}/5] Posso mostrar-te algo amanhã?"
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = f"<{tracking_hash}@{account['full_domain']}>"
        
        # Aplicar mutação
        html_content = apply_mutation(
            EMAIL_TEMPLATE_HTML,
            tracking_hash,
            recipient,
            email_num
        )
        
        msg.attach(MIMEText("Ver versão em HTML", 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        # Assinar
        signed_message = sign_email_with_dkim(msg, account)
        
        # Enviar via SMTP
        host = account.get('kumomta_host', 'localhost')
        port = account.get('kumomta_port', 2525)
        
        logger.info(f"  → Conectando ao SMTP ({host}:{port})...")
        
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            try:
                smtp.starttls()
            except:
                pass
            
            result = smtp.sendmail(
                account['address'],
                recipient,
                signed_message
            )
            
            logger.info(f"  ✓ Email enviado: {recipient}")
            return True
            
    except Exception as e:
        logger.error(f"  ✗ Erro ao enviar para {recipient}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    logger.info("=" * 80)
    logger.info("ENVIO DE EMAILS DE TESTE")
    logger.info("=" * 80)
    
    try:
        account = load_account_from_hf()
        
        logger.info(f"\nEnviando {len(TEST_RECIPIENTS)} emails de teste...\n")
        
        results = {}
        for idx, recipient in enumerate(TEST_RECIPIENTS, 1):
            tracking_hash = generate_tracking_hash(account['address'], recipient)
            
            logger.info(f"\n[{idx}/{len(TEST_RECIPIENTS)}] {recipient}")
            success = send_email_via_smtp(account, recipient, tracking_hash, email_num=1)
            
            results[recipient] = {
                "success": success,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "account": account['address'],
                "tracking_hash": tracking_hash
            }
        
        logger.info("\n" + "=" * 80)
        logger.info("RESUMO DE ENVIO:")
        logger.info("=" * 80)
        
        success_count = sum(1 for r in results.values() if r['success'])
        logger.info(f"✓ Sucesso: {success_count}/{len(TEST_RECIPIENTS)}")
        
        for recipient, result in results.items():
            status = "✓" if result['success'] else "✗"
            logger.info(f"  {status} {recipient}")
        
        logger.info("=" * 80)
        
        return success_count == len(TEST_RECIPIENTS)
        
    except Exception as e:
        logger.error(f"\n✗ ERRO FATAL: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
