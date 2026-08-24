import os
import sys
import time
import requests
import smtplib
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
ROUTE64_IPV6_RAW = os.environ.get("ROUTE64_IPV6", "")
ROUTE64_IPV6 = ROUTE64_IPV6_RAW.split("/")[0] if ROUTE64_IPV6_RAW else ""

def log(tag, msg, success=True):
    icon = "✓" if success else "✗"
    print(f"[{icon}] [{tag}] {msg}")

# --- STEP 1: CONFIGURAR rDNS NA ROUTE64 ---
def setup_route64_rdns():
    print("\n--- 🌐 STEP 1: CONFIGURANDO rDNS NA ROUTE64 ---")
    if not ROUTE64_API_KEY or not ROUTE64_IPV6:
        log("ROUTE64", "ROUTE64_API_KEY ou ROUTE64_IPV6 não configuradas corretamente.", False)
        return

    headers = {
        "Authorization": f"Bearer {ROUTE64_API_KEY}",
        "Content-Type": "application/json"
    }
    url = f"https://manager.route64.org/api/rdns/{ROUTE64_IPV6}"
    payload = {"hostname": SUBDOMAIN}
    
    try:
        res = requests.put(url, json=payload, headers=headers, timeout=10)
        if res.status_code in [200, 201, 204]:
            log("ROUTE64", f"rDNS atualizado com sucesso! IP: {ROUTE64_IPV6} -> {SUBDOMAIN}")
        else:
            # Se PUT falhar, tenta via POST create
            res_post = requests.post("https://manager.route64.org/api/rdns/create", json={"ip": ROUTE64_IPV6, "hostname": SUBDOMAIN}, headers=headers, timeout=10)
            log("ROUTE64", f"Resposta criação rDNS: HTTP {res_post.status_code} - {res_post.text}")
    except Exception as e:
        log("ROUTE64", f"Erro na requisição à API Route64: {str(e)}", False)

# --- STEP 2: GERAR CHAVES DKIM ---
def generate_dkim_keys():
    print("\n--- 🔑 STEP 2: GERANDO CHAVE DKIM RSA 2048 ---")
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
    log("DKIM", "Par de chaves gerado com sucesso!")
    return pem_private, pub_b64

# --- STEP 3: PUBLICAR REGISTOS SPF, DKIM E DMARC NO DESEC ---
def setup_desec_dns(pub_b64_key):
    print("\n--- 📡 STEP 3: ATUALIZANDO DNS NO DESEC ---")
    headers = {
        "Authorization": f"Token {DESEC_TOKEN}",
        "Content-Type": "application/json",
    }
    
    # Inclui o IPv6 da Route64 explicitamente no SPF
    spf_val = f'"v=spf1 ip6:{ROUTE64_IPV6} a mx ~all"' if ROUTE64_IPV6 else '"v=spf1 a mx ~all"'
    
    records = [
        {"subdomain": "sub", "type": "TXT", "ttl": 3600, "records": [spf_val]},
        {"subdomain": "default._domainkey.sub", "type": "TXT", "ttl": 3600, "records": [f'"v=DKIM1; k=rsa; p={pub_b64_key}"']},
        {"subdomain": "_dmarc.sub", "type": "TXT", "ttl": 3600, "records": ['"v=DMARC1; p=none; sp=none; pct=100;"']}
    ]
    
    for rr in records:
        url = f"https://desec.io/api/v1/domains/{DOMAIN_BASE}/rrsets/"
        payload = {"subdomain": rr["subdomain"], "type": rr["type"], "ttl": rr["ttl"], "records": rr["records"]}
        res = requests.post(url, json=payload, headers=headers)
        if res.status_code in [200, 201]:
            log("deSEC", f"Registo {rr['type']} adicionado para '{rr['subdomain']}'")
        else:
            patch_url = f"{url}{rr['subdomain']}/{rr['type']}/"
            patch_res = requests.patch(patch_url, json={"records": rr["records"]}, headers=headers)
            if patch_res.status_code in [200, 204]:
                log("deSEC", f"Registo {rr['type']} atualizado para '{rr['subdomain']}'")
            else:
                log("deSEC", f"Erro no registo {rr['type']}: {patch_res.text}", False)

# --- STEP 4: ENVIO SMTP ASSINADO COM LOGO VERISCOPE ---
def send_test_emails(private_key_pem):
    print("\n--- ✉️ STEP 4: DISPARANDO E-MAILS ---")
    subject = "Liquidity Alert: Atualização de Mercado Veriscope"
    
    # Template HTML em Dark Mode com a marca Veriscope
    html_content = """\
    <!DOCTYPE html>
    <html>
      <body style="background-color: #000000; color: #ffffff; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; padding: 30px; margin: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #0a0a0a; border: 1px solid #222222; border-radius: 8px; padding: 30px;">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #d4af37; font-size: 24px; letter-spacing: 2px; margin: 0;">VERISCOPE</h1>
            <p style="color: #888888; font-size: 12px; margin-top: 5px;">INTELLIGENCE & MARKET EDGE</p>
          </div>
          <hr style="border: 0; border-top: 1px solid #222222; margin: 20px 0;"/>
          <h2 style="color: #ffffff; font-size: 18px;">Alerta de Liquidez Detectado</h2>
          <p style="color: #cccccc; line-height: 1.6;">Este é um e-mail de teste de verificação de entregabilidade direta na Caixa de Entrada (Inbox) utilizando a infraestrutura de rede da Route64 e deSEC.</p>
          <div style="background-color: #141414; border-left: 3px solid #d4af37; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="margin: 0; color: #d4af37; font-weight: bold;">Remetente:</p>
            <p style="margin: 5px 0 0 0; color: #ffffff;">Alex | Liquidity Alert &lt;alex@sub.veriscope.dedyn.io&gt;</p>
          </div>
          <p style="color: #888888; font-size: 12px; text-align: center; margin-top: 30px;">
            © 2026 Veriscope. Todos os direitos reservados.
          </p>
        </div>
      </body>
    </html>
    """

    for recipient in RECIPIENTS:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{Header(SENDER_NAME, 'utf-8')} <{SENDER_EMAIL}>"
        msg["To"] = recipient
        msg["Subject"] = Header(subject, "utf-8")
        msg.attach(MIMEText(html_content, "html", "utf-8"))

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
            log("DKIM", f"Falha ao assinar para {recipient}: {str(e)}", False)
            continue

        try:
            with smtplib.SMTP("localhost", 25) as server:
                server.sendmail(SENDER_EMAIL, [recipient], raw_msg)
            log("SMTP", f"Mensagem entregue ao Postfix local para: {recipient}")
        except Exception as e:
            log("SMTP", f"Erro no envio SMTP para {recipient}: {str(e)}", False)

if __name__ == "__main__":
    setup_route64_rdns()
    priv_key, pub_key_b64 = generate_dkim_keys()
    setup_desec_dns(pub_key_b64)
    
    print("\n⏳ Aguardando 10 segundos para propagação do DNS...")
    time.sleep(10)
    
    send_test_emails(priv_key)
