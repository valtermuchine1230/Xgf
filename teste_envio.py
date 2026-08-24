import os
import sys
import time
import requests
import dkim
import smtplib
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==========================================
# CONFIGURAÇÕES E CHAVES
# ==========================================
ROUTE64_API_KEY = os.getenv("ROUTE64_API_KEY", "I7ACbK9fsRD5ZNCHvD7FtjcoOYmhgz1MNTyh3rxgdFc")
ROUTE64_IPV6 = "2a11:6c7:f10:5::2"
DOMAIN = "veriscope.dedyn.io"
SUBDOMAIN = "sub.veriscope.dedyn.io"

# Token extraído do painel deSEC
DESEC_TOKEN = os.getenv("DESEC_TOKEN", "NGRQaMUdKpxor1EArnfYdxpGgPSb")

RECIPIENTS = [
    "macuacuavalter71@gmail.com",
    "stanl-eyb-75@aliasvault.net",
    "au-sbrooks80@aliasvault.net",
    "probbins87@aliasvault.net",
    "Info1yenom@gmail.com"
]

print("--- 🌐 STEP 1: CONFIGURANDO rDNS NA ROUTE64 ---")
try:
    # A API oficial do Route64 exige percent-encoding do IPv6 na URL (manager.route64.org)
    encoded_ipv6 = urllib.parse.quote(ROUTE64_IPV6)
    url_rdns = f"https://manager.route64.org/api/rdns/{encoded_ipv6}/"
    
    headers_r64 = {
        "Authorization": f"Bearer {ROUTE64_API_KEY}",
        "Content-Type": "application/json"
    }
    payload_r64 = {"rdns": SUBDOMAIN}

    res = requests.put(url_rdns, json=payload_r64, headers=headers_r64, timeout=10)
    print(f"[✓] [ROUTE64] Configuração rDNS ({ROUTE64_IPV6} -> {SUBDOMAIN}): Status {res.status_code}")
    if res.status_code not in [200, 201, 204]:
        print(f"    Detalhes Route64: {res.text}")
except Exception as e:
    print(f"[✗] [ROUTE64] Erro na requisição rDNS: {e}")

print("\n--- 🔑 STEP 2: GERANDO CHAVE DKIM RSA 2048 ---")
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pub_lines = public_pem.decode('utf-8').splitlines()[1:-1]
    pub_base64 = "".join(pub_lines)
    print("[✓] [DKIM] Par de chaves gerado com sucesso!")
except Exception as e:
    print(f"[✗] [DKIM] Erro ao gerar chaves: {e}")
    sys.exit(1)

print("\n--- 📡 STEP 3: ATUALIZANDO DNS NO DESEC ---")
desec_headers = {
    "Authorization": f"Token {DESEC_TOKEN}",
    "Content-Type": "application/json"
}

def update_desec_rrset(subname, record_type, records_list):
    # Endpoint da API REST deSEC conforme documentacao readthedocs
    url = f"https://desec.io/api/v1/domains/{DOMAIN}/rrsets/"
    
    # Formatação exata do payload deSEC para registos TXT
    formatted_records = [f'"{r}"' if not r.startswith('"') else r for r in records_list]
    
    payload = {
        "subname": subname,
        "type": record_type,
        "ttl": 3600,
        "records": formatted_records
    }
    
    # Tenta criar via POST; se já existir, faz update com PUT no RRset específico
    r = requests.post(url, json=payload, headers=desec_headers, timeout=10)
    if r.status_code == 409: # Recordset ja existe
        rrset_url = f"{url}{subname}/{record_type}/"
        r = requests.put(rrset_url, json=payload, headers=desec_headers, timeout=10)
        
    if r.status_code in [200, 201]:
        print(f"[✓] [deSEC] Registado {record_type} em ({subname}.{DOMAIN}) com sucesso!")
    else:
        print(f"[✗] [deSEC] Erro no registo {record_type} ({subname}): HTTP {r.status_code} - {r.text}")

# 1. Registro SPF
update_desec_rrset("sub", "TXT", [f"v=spf1 ip6:{ROUTE64_IPV6} ~all"])

# 2. Registro DKIM
update_desec_rrset("default._domainkey.sub", "TXT", [f"v=DKIM1; k=rsa; p={pub_base64}"])

# 3. Registro DMARC
update_desec_rrset("_dmarc.sub", "TXT", ["v=DMARC1; p=none; sp=none; pct=100"])

print("\n⏳ Aguardando 10 segundos para propagação do DNS...")
time.sleep(10)

print("\n--- ✉️ STEP 4: DISPARANDO E-MAILS ---")
for recipient in RECIPIENTS:
    msg = MIMEMultipart("alternative")
    msg["From"] = f"Alex <alex@{SUBDOMAIN}>"
    msg["To"] = recipient
    msg["Subject"] = "Teste de Entregabilidade Veriscope"
    msg["Message-ID"] = f"<{time.time()}@{SUBDOMAIN}>"

    body = "E-mail de teste enviado via Postfix + Route64 WireGuard + deSEC DNS."
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Assinar via DKIM
    sig = dkim.sign(
        message=msg.as_bytes(),
        selector=b"default",
        domain=SUBDOMAIN.encode('utf-8'),
        privkey=private_pem,
        include_headers=[b"From", b"To", b"Subject", b"Message-ID"]
    )
    msg_signed = sig + msg.as_bytes()

    try:
        with smtplib.SMTP("127.0.0.1", 25) as server:
            server.sendmail(f"alex@{SUBDOMAIN}", [recipient], msg_signed)
            print(f"[✓] [SMTP] Mensagem entregue ao Postfix local para: {recipient}")
    except Exception as e:
        print(f"[✗] [SMTP] Erro ao enviar para {recipient}: {e}")
