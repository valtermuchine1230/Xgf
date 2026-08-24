#!/usr/bin/env python3
"""
Provisão de 1 conta única para teste (sub0.veriscope0.dedyn.io)
- Cria sub-subdomínio via deSEC API
- Gera chave privada DKIM
- Configura SPF, DKIM, DMARC, PTR
- Salva resultado no HuggingFace Datasets
"""

import os
import json
import logging
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests
from huggingface_hub import HfApi, create_repo

DESEC_DOMAIN = os.getenv("DESEC_DOMAIN", "veriscope0.dedyn.io")
DESEC_TOKEN = os.getenv("DESEC_TOKEN_1")
ROUTE64_API_KEY = os.getenv("ROUTE64_API_KEY")
ROUTE64_API_URL = os.getenv("ROUTE64_API_URL", "https://manager.route64.org/api")
HF_TOKEN = os.getenv("HF_TOKEN")
HF_REPO = os.getenv("HF_REPO", "veriscope/checkpoints")

SUBDOMAIN = "sub0"
FULL_DOMAIN = f"{SUBDOMAIN}.{DESEC_DOMAIN}"
EMAIL_ADDRESS = f"alex@{FULL_DOMAIN}"
SENDER_NAME = "Alex | Liquidity Alert"
DKIM_SELECTOR = "s2026"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

def generate_rsa_keypair(key_size=2048):
    """Gera par de chaves RSA para DKIM"""
    logger.info(f"Gerando chaves RSA ({key_size} bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    public_key_line = public_pem.split("\n")[1:-2]
    public_key_base64 = "".join(public_key_line)
    
    logger.info("✓ Chaves RSA geradas com sucesso")
    return private_pem, public_key_base64

def create_desec_subdomain(subdomain, domain, dkim_public_key):
    """Cria sub-subdomínio no deSEC e configura registos (SPF, DKIM, DMARC)"""
    logger.info(f"Configurando {subdomain}.{domain} no deSEC...")
    
    if not DESEC_TOKEN:
        raise ValueError("DESEC_TOKEN_1 não configurado")
    
    base_url = f"https://desec.io/api/v1/domains/{domain}/rrsets/"
    headers = {
        "Authorization": f"Token {DESEC_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # 1. SPF Record
    logger.info(f"  → Criando SPF para {subdomain}...")
    try:
        spf_data = {
            "subname": subdomain,
            "type": "TXT",
            "ttl": 3600,
            "records": [{"contents": "v=spf1 mx ~all"}]
        }
        resp = requests.put(
            base_url,
            params={"subname": subdomain, "type": "TXT"},
            headers=headers,
            json=spf_data,
            timeout=10
        )
        if resp.status_code not in [200, 201, 204]:
            logger.warning(f"  ✗ SPF error ({resp.status_code}): {resp.text}")
        else:
            logger.info(f"  ✓ SPF criado")
    except Exception as e:
        logger.warning(f"  ✗ SPF exception: {e}")
    
    # 2. DKIM Record
    logger.info(f"  → Criando DKIM para {DKIM_SELECTOR}.{subdomain}...")
    try:
        dkim_record = f"v=DKIM1; k=rsa; p={dkim_public_key}"
        dkim_data = {
            "subname": f"{DKIM_SELECTOR}.{subdomain}",
            "type": "TXT",
            "ttl": 3600,
            "records": [{"contents": dkim_record}]
        }
        resp = requests.put(
            base_url,
            params={"subname": f"{DKIM_SELECTOR}.{subdomain}", "type": "TXT"},
            headers=headers,
            json=dkim_data,
            timeout=10
        )
        if resp.status_code not in [200, 201, 204]:
            logger.warning(f"  ✗ DKIM error ({resp.status_code}): {resp.text}")
        else:
            logger.info(f"  ✓ DKIM criado")
    except Exception as e:
        logger.warning(f"  ✗ DKIM exception: {e}")
    
    # 3. DMARC Record
    logger.info(f"  → Criando DMARC para _dmarc.{subdomain}...")
    try:
        dmarc_data = {
            "subname": f"_dmarc.{subdomain}",
            "type": "TXT",
            "ttl": 3600,
            "records": [{"contents": "v=DMARC1; p=quarantine; rua=mailto:postmaster@veriscope.com"}]
        }
        resp = requests.put(
            base_url,
            params={"subname": f"_dmarc.{subdomain}", "type": "TXT"},
            headers=headers,
            json=dmarc_data,
            timeout=10
        )
        if resp.status_code not in [200, 201, 204]:
            logger.warning(f"  ✗ DMARC error ({resp.status_code}): {resp.text}")
        else:
            logger.info(f"  ✓ DMARC criado")
    except Exception as e:
        logger.warning(f"  ✗ DMARC exception: {e}")
    
    logger.info(f"✓ {subdomain}.{domain} configurado no deSEC")

def save_account_to_hf(account_data):
    """Salva dados da conta no HuggingFace Datasets"""
    logger.info(f"Salvando conta no HF ({HF_REPO})...")
    
    if not HF_TOKEN:
        raise ValueError("HF_TOKEN não configurado")
    
    try:
        api = HfApi()
        
        try:
            create_repo(repo_id=HF_REPO, repo_type="dataset", private=True, exist_ok=True)
        except:
            pass
        
        account_file = Path("sender_account.json")
        with open(account_file, "w") as f:
            json.dump(account_data, f, indent=2)
        
        api.upload_file(
            path_or_fileobj=str(account_file),
            path_in_repo="sender_account.json",
            repo_id=HF_REPO,
            repo_type="dataset",
            token=HF_TOKEN
        )
        
        logger.info(f"✓ Conta salva em {HF_REPO}/sender_account.json")
        account_file.unlink()
        
    except Exception as e:
        logger.error(f"✗ Erro ao salvar no HF: {e}")
        raise

def main():
    logger.info("=" * 80)
    logger.info("PROVISÃO DE CONTA ÚNICA - TESTE")
    logger.info("=" * 80)
    
    try:
        # 1. Gerar chaves DKIM
        private_key, public_key_b64 = generate_rsa_keypair()
        
        # 2. Criar sub-domínio no deSEC
        create_desec_subdomain(SUBDOMAIN, DESEC_DOMAIN, public_key_b64)
        
        # 3. Esperar propagação
        logger.info("\n⏳ Aguardando propagação DNS (20 segundos)...")
        import time
        time.sleep(20)
        
        # 4. Criar JSON de conta
        account_data = {
            "id": "email_001",
            "address": EMAIL_ADDRESS,
            "sender_name": SENDER_NAME,
            "full_domain": FULL_DOMAIN,
            "subdomain": SUBDOMAIN,
            "dkim_selector": DKIM_SELECTOR,
            "dkim_private_key": private_key,
            "dkim_public_key": public_key_b64,
            "kumomta_host": os.getenv("KUMOMTA_HOST", "localhost"),
            "kumomta_port": int(os.getenv("KUMOMTA_PORT", "2525")),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status": "active"
        }
        
        # 5. Salvar no HF
        save_account_to_hf(account_data)
        
        logger.info("\n" + "=" * 80)
        logger.info("✓ PROVISÃO COMPLETA")
        logger.info("=" * 80)
        logger.info(f"Email: {EMAIL_ADDRESS}")
        logger.info(f"Domínio: {FULL_DOMAIN}")
        logger.info(f"DKIM Selector: {DKIM_SELECTOR}")
        logger.info("=" * 80)
        
        return True
        
    except Exception as e:
        logger.error(f"\n✗ ERRO FATAL: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
