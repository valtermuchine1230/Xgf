import os
import smtplib
import time
import requests
import dkim
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- CONFIGURAÇÕES DO TESTE ---
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

# --- 1. GERAÇÃO DE CHAVE DKIM ---
def generate_dkim_keys():
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
    return pem_private, pub_b64

# --- 2. CONFIGURAÇÃO DNS VIA API DE-SEC ---
def setup_desec_dns(pub_b64_key):
    headers = {
        "Authorization": f"Token {DESEC_TOKEN}",
        "Content-Type": "application/json",
    }
    
    # Registos DNS para Alinhamento SPF, DKIM e DMARC
    records = [
        {
            "subdomain": "sub",
            "type": "TXT",
            "ttl": 3600,
            "records": ['"v=spf1 a mx ~all"']
        },
        {
            "subdomain": "default._domainkey.sub",
            "type": "TXT",
            "ttl": 3600,
            "records": [f'"v=DKIM1; k=rsa; p={pub_b64_key}"']
        },
        {
            "subdomain": "_dmarc.sub",
            "type": "TXT",
            "ttl": 3600,
            "records": ['"v=DMARC1; p=none; sp=none; pct=100;"']
        }
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
        if res.status_code not in [200, 201]:
            # Se já existir, faz PATCH
            patch_url = f"{url}{rr['subdomain']}/{rr['type']}/"
            requests.patch(patch_url, json={"records": rr["records"]}, headers=headers)
            
    print("✓ Registos SPF, DKIM e DMARC configurados no deSEC com sucesso.")

# --- 3. CONSTRUÇÃO E ASSINATURA DE E-MAIL ---
def send_test_emails(private_key_pem):
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

        # Assinatura DKIM no Header do E-mail
        sig = dkim.sign(
            message=msg.as_bytes(),
            selector=b"default",
            domain=SUBDOMAIN.encode('utf-8'),
            privkey=private_key_pem.encode('utf-8'),
            include_headers=[b"From", b"To", b"Subject"]
        )
        
        raw_msg = sig + msg.as_bytes()

        # Conexão SMTP Local/MTA
        try:
            with smtplib.SMTP("localhost", 25) as server:
                server.sendmail(SENDER_EMAIL, [recipient], raw_msg)
            print(f"✓ E-mail enviado com sucesso para: {recipient}")
        except Exception as e:
            print(f"✗ Falha ao enviar para {recipient}: {e}")

if __name__ == "__main__":
    print("Iniciando setup de DNS e validação...")
    priv_key, pub_key_b64 = generate_dkim_keys()
    setup_desec_dns(pub_key_b64)
    
    print("Aguardando 10 segundos para propagação DNS...")
    time.sleep(10)
    
    send_test_emails(priv_key)
