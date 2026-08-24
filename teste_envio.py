import os
import sys
import time
import json
import smtplib
import requests
import dkim
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- CONFIGURAÇÕES ---
DESEC_TOKEN = "M7EZnMkjgErWvgFRwMtFi2DD9vbB"
DOMAIN_BASE = "veriscope.dedyn.io"
SUBDOMAIN = "sub.veriscope.dedyn.io"
SENDER_EMAIL = "alex@sub.veriscope.dedyn.io"
SENDER_NAME = "Alex | Liquidity Alert"

RECIPIENTS = [
    "macuacuavalter71@gmail.com",
    "stanl-eyb-75@aliasvault.net",
    "au-sbrooks80@aliasvault.net",
    "probbins87@aliasvault.net",
    "Info1yenom@gmail.com"
]

ROUTE64_API_KEY = os.environ.get("ROUTE64_API_KEY")

def log(tag, msg, success=True):
    icon = "✓" if success else "✗"
    print(f"[{icon}] [{tag}] {msg}")

# --- STEP 1: ROUTE64 rDNS CONFIGURATION ---
def setup_route64_rdns():
    print("\n--- 🌐 STEP 1: CONFIGURANDO ROUTE64 (rDNS) ---")
    if not ROUTE64_API_KEY:
        log("ROUTE64", "Chave ROUTE64_API_KEY não encontrada nas secrets do GitHub!", False)
        return
    
    headers = {"Authorization": f"Bearer {ROUTE64_API_KEY}", "Content-Type": "application/json"}
    url = "https://manager.route64.org/api/rdns/create"
    payload = {"hostname": SUBDOMAIN}
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        if res.status_code in [200, 201]:
            log("ROUTE64", f"rDNS atualizado com sucesso para '{SUBDOMAIN}'. Resposta: {res.text}")
        else:
            log("ROUTE64", f"Falha ao atualizar rDNS. HTTP {res.status_code}: {res.text}", False)
    except Exception as e:
        log("ROUTE64", f"Erro de conexão com API Route64: {str(e)}", False)

# --- STEP 2: DKIM GENERATION ---
def generate_dkim_keys():
    print("\n--- 🔑 STEP 2: GERANDO CHAVES DKIM (RSA 2048) ---")
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        der_public = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        import base64
        pub_b64 = base64.b64encode(der_public).decode('utf-8')
        log("DKIM", "Par de chaves RSA 2048 gerado com sucesso!")
        return pem_private, pub_b64
    except Exception as e:
        log("DKIM", f"Erro ao gerar chaves DKIM: {str(e)}", False)
        sys.exit(1)

# --- STEP 3: DESEC DNS CONFIGURATION ---
def setup_desec_dns(pub_b64_key):
    print("\n--- 📡 STEP 3: PUBLICANDO REGISTOS DNS NO DESEC ---")
    headers = {
        "Authorization": f"Token {DESEC_TOKEN}",
        "Content-Type": "application/json",
    }
    
    records = [
        {"subdomain": "sub", "type": "TXT", "ttl": 3600, "records": ['"v=spf1 a mx ~all"']},
        {"subdomain": "default._domainkey.sub", "type": "TXT", "ttl": 3600, "records": [f'"v=DKIM1; k=rsa; p={pub_b64_key}"']},
        {"subdomain": "_dmarc.sub", "type": "TXT", "ttl": 3600, "records": ['"v=DMARC1; p=none; sp=none; pct=100;"']}
    ]
    
    for rr in records:
        url = f"https://desec.io/api/v1/domains/{DOMAIN_BASE}/rrsets/"
        payload = {
            "subdomain": rr["subdomain"],
            "type": rr["type"],
            "ttl": rr["ttl"],
            "records": rr["records"]
        }
        res = requests.post(url, json=payload, headers=headers)
        if res.status_code in [200, 201]:
            log("deSEC", f"Registo {rr['type']} criado para '{rr['subdomain']}.{DOMAIN_BASE}'")
        else:
            # Tenta atualizar (PATCH) caso já exista
            patch_url = f"{url}{rr['subdomain']}/{rr['type']}/"
            patch_res = requests.patch(patch_url, json={"records": rr["records"]}, headers=headers)
            if patch_res.status_code in [200, 204]:
                log("deSEC", f"Registo {rr['type']} atualizado para '{rr['subdomain']}.{DOMAIN_BASE}'")
            else:
                log("deSEC", f"Erro no registo {rr['type']} ({rr['subdomain']}): HTTP {patch_res.status_code} - {patch_res.text}", False)

# --- STEP 4: DISPARO SMTP VIA POSTFIX ---
def send_test_emails(private_key_pem):
    print("\n--- ✉️ STEP 4: INICIANDO DISPARO DE TESTE SMTP ---")
    subject = "Liquidity Alert: Atualização do Mercado Veriscope"
    html_content = """\
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <h2>Alertas de Liquidez Veriscope</h2>
        <p>Olá,</p>
        <p>Este é um e-mail de teste de verificação de entregabilidade (Inbox Rate 10/10).</p>
        <p><strong>Remetente:</strong> Alex | Liquidity Alert</p>
        <hr/>
        <p style="font-size: 12px; color: #777;">Veriscope Engine - All Rights Reserved.</p>
      </body>
    </html>
    """

    for recipient in RECIPIENTS:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{Header(SENDER_NAME, 'utf-8')} <{SENDER_EMAIL}>"
        msg["To"] = recipient
        msg["Subject"] = Header(subject, "utf-8")
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        # Assinatura DKIM
        try:
            sig = dkim.sign(
                message=msg.as_bytes(),
                selector=b"default",
                domain=SUBDOMAIN.encode('utf-8'),
                privkey=private_key_pem.encode('utf-8'),
                include_headers=[b"From", b"To", b"Subject"]
            )
            raw_msg = sig + msg.as_bytes()
        except Exception as e:
            log("DKIM-SIGN", f"Erro ao assinar e-mail para {recipient}: {str(e)}", False)
            continue

        # Envio local para o Postfix
        try:
            with smtplib.SMTP("localhost", 25) as server:
                server.set_debuglevel(1)  # Mostra a conversa SMTP em tempo real no console
                server.sendmail(SENDER_EMAIL, [recipient], raw_msg)
            log("SMTP-QUEUE", f"E-mail entregue à fila do Postfix para: {recipient}")
        except Exception as e:
            log("SMTP-ERROR", f"Falha ao conectar/enviar via SMTP local para {recipient}: {str(e)}", False)

if __name__ == "__main__":
    setup_route64_rdns()
    priv_key, pub_key_b64 = generate_dkim_keys()
    setup_desec_dns(pub_key_b64)
    
    print("\n⏳ Aguardando 10 segundos para propagação inicial dos DNS...")
    time.sleep(10)
    
    send_test_emails(priv_key)
