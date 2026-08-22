#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VERISCOPE EMAIL ENGINE v3.0 — ALL-IN-ONE
=========================================
- 25 domínios principais: veriscope0.dedyn.io ... veriscope24.dedyn.io
- 3000 contas distribuídas: 120 contas por domínio
- Sub-subdomínios: subXXX.veriscopeN.dedyn.io
- Emails de teste fixos (5 emails)
- Tracking de abertura (pixel)
- Mutação de conteúdo (fuzzy hash evasion)
- Provisionamento automático com rate limiting
- Shutdown 5h30 + auto-dispatch
- Idempotência + déficit completion
- Checkpoints no HuggingFace

Autor: Valter3B
Data: 2026-08-22
"""

from __future__ import annotations

import os
import sys
import json
import time
import signal
import asyncio
import logging
import hashlib
import random
import base64
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event

# ============================================================================
# IMPORTS DE TERCEIROS
# ============================================================================

try:
    import aiosmtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
except ImportError:
    print("❌ aiosmtplib não instalado. Execute: pip install aiosmtplib")
    sys.exit(1)

try:
    from huggingface_hub import HfApi, hf_hub_download
except ImportError:
    print("❌ huggingface-hub não instalado. Execute: pip install huggingface-hub")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("❌ pandas não instalado. Execute: pip install pandas")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("❌ cryptography não instalado. Execute: pip install cryptography")
    sys.exit(1)

try:
    import dkim
except ImportError:
    print("❌ dkimpy não instalado. Execute: pip install dkimpy")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("❌ requests não instalado. Execute: pip install requests")
    sys.exit(1)

try:
    from tenacity import retry, stop_after_attempt, wait_exponential
except ImportError:
    print("❌ tenacity não instalado. Execute: pip install tenacity")
    sys.exit(1)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from email_validator import validate_email, EmailNotValidError
except ImportError:
    print("❌ email-validator não instalado. Execute: pip install email-validator")
    sys.exit(1)


# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

SAVE_PATH = Path(os.environ.get("SAVE_PATH", "./data"))
SAVE_PATH.mkdir(parents=True, exist_ok=True)

STATE_PATH = SAVE_PATH / "send_state.json"
ACCOUNTS_PATH = SAVE_PATH / "sender_accounts.json"
LOG_PATH = SAVE_PATH / "veriscope.log"
IDEMPOTENCY_PATH = SAVE_PATH / "idempotency.parquet"

# ============================================================================
# LOGGING
# ============================================================================

class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record):
        levelname = record.levelname
        color = self.COLORS.get(levelname, self.RESET)
        record.levelname = f"{color}{self.BOLD}{levelname:8s}{self.RESET}"
        return super().format(record)

def setup_logging(log_path: Path, log_level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("veriscope")
    logger.setLevel(log_level)
    logger.handlers = []

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = ColoredFormatter(
        fmt="%(asctime)s │ %(levelname)s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)

    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)s │ %(funcName)s:%(lineno)d │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

logger = setup_logging(LOG_PATH, os.environ.get("LOG_LEVEL", "INFO"))


# ============================================================================
# EMOJIS / ICONES
# ============================================================================

E = {
    "start": "🚀", "download": "📥", "extract": "📦", "stats": "📊",
    "space": "💾", "email": "📧", "upload": "📤", "clean": "🧹",
    "warn": "⚠️", "error": "❌", "ok": "✅", "info": "ℹ️",
    "cpu": "⚙️", "clock": "⏱️", "list": "📋", "db": "🗄️",
    "monitor": "📡", "limit": "🛑", "debug": "🔍", "valid": "✓",
    "folder": "📁", "check": "✔️", "recover": "🔄", "save": "💾",
    "test": "🧪", "test_ok": "✅", "prod": "🏭", "smtp": "📮",
    "account": "👤", "accounts": "👥", "lock": "🔒", "unlock": "🔓",
    "shutdown": "⏰", "dispatch": "🔄", "completed": "🎉",
}


# ============================================================================
# CONFIGLOADER — CARREGA VARIÁVEIS DE AMBIENTE
# ============================================================================

class ConfigLoader:
    """Carrega e valida todas as configurações do ambiente."""

    def __init__(self):
        # HuggingFace
        self.hf_token = os.getenv("HF_TOKEN")
        self.hf_repo_emails = os.getenv("HF_REPO_EMAILS", "Valter3B/Trader_Emails")
        self.hf_repo_checkpoint = os.getenv("HF_REPO_CHECKPOINT", "Valter3B/veriscope_checkpoints")

        # KumoMTA
        self.kumomta_host = os.getenv("KUMOMTA_HOST", "127.0.0.1")
        self.kumomta_port = int(os.getenv("KUMOMTA_PORT", "2525"))

        # Domínios principais (25 domínios)
        self.desec_domains = [f"veriscope{i}.dedyn.io" for i in range(25)]
        self.desec_tokens = self._load_desec_tokens()  # esperamos 25 tokens

        # Route64
        self.route64_api_key = os.getenv("ROUTE64_API_KEY")

        # Configuração da campanha
        self.from_name = os.getenv("FROM_NAME", "Alex | Liquidity Alert")
        self.days = 5
        self.emails_per_day = 30_000_000
        self.total_emails = self.emails_per_day * self.days

        # Limites
        self.quota_per_account_per_domain = 50
        self.shutdown_minutes = 330
        self.graceful_wait_seconds = 180
        self.checkpoint_interval_seconds = 300

        # Número de contas a criar
        self.num_accounts = 3000

        # Emails de teste (fixos)
        self.test_emails = [
            "macuacuavalter71@gmail.com",
            "stanl-eyb-75@aliasvault.net",
            "au-sbrooks80@aliasvault.net",
            "probbins87@aliasvault.net",
            "Info1yenom@gmail.com"
        ]

        self._validate()

    def _load_desec_tokens(self) -> List[str]:
        tokens = []
        for i in range(1, 26):  # 25 tokens (1 a 25)
            token = os.getenv(f"DESEC_TOKEN_{i}")
            if token:
                tokens.append(token)
        if len(tokens) < 25:
            logger.warning(f"{E['warn']} Apenas {len(tokens)} tokens deSEC encontrados. Esperava 25.")
        return tokens

    def _validate(self):
        if not self.hf_token:
            raise ValueError("HF_TOKEN não definido")
        logger.info(f"{E['ok']} Configuração carregada: {len(self.desec_tokens)} tokens, {len(self.test_emails)} emails de teste")

config = ConfigLoader()


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class SenderAccount:
    id: str                     # "email_001"
    email: str                  # "alex@sub001.veriscope0.dedyn.io"
    domain: str                 # "sub001.veriscope0.dedyn.io"
    main_domain: str            # "veriscope0.dedyn.io"
    ipv6: str
    dkim_selector: str          # "s2026"
    dkim_private_key: str
    dkim_public_key: str
    status: str                 # "active", "paused", "warming"
    created_at: str
    last_used: Optional[str] = None
    total_sent: int = 0
    daily_sent: Dict[str, int] = field(default_factory=dict)


@dataclass
class CampaignState:
    status: str
    session_number: int
    current_day: int
    current_account_index: int
    current_domain: str
    total_sent_global: int
    total_sent_this_session: int
    runs_without_progress: int
    last_checkpoint: str
    completed_domains: List[str]
    pending_completion: Dict[str, int]
    hash_sha256: str = ""


# ============================================================================
# DKIM MANAGER
# ============================================================================

class DKIMManager:
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
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

    @staticmethod
    def sign_message(message: bytes, private_key_pem: str, domain: str, selector: str = "s2026") -> bytes:
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
            logger.error(f"{E['error']} DKIM signing error: {e}")
            return message


# ============================================================================
# PROVISIONING MANAGER — CRIA 25 DOMÍNIOS E 3000 CONTAS
# ============================================================================

class ProvisioningManager:
    def __init__(self):
        self.desec_domains = config.desec_domains  # 25 domínios
        self.desec_tokens = config.desec_tokens    # 25 tokens
        self.route64_api_key = config.route64_api_key
        self.num_accounts = config.num_accounts
        self.hf_api = HfApi()

    def create_account(self, account_index: int) -> Optional[SenderAccount]:
        """
        Cria uma conta:
        - Distribui pelos domínios principais (round-robin)
        - Cria sub-subdomínio subXXX.veriscopeN.dedyn.io
        """
        try:
            # Determinar qual domínio principal usar (round-robin)
            num_domains = len(self.desec_domains)
            domain_idx = account_index % num_domains
            main_domain = self.desec_domains[domain_idx]
            token = self.desec_tokens[domain_idx] if domain_idx < len(self.desec_tokens) else None

            # Gerar sub-subdomínio
            sub_name = f"sub{account_index:04d}"
            full_domain = f"{sub_name}.{main_domain}"
            account_id = f"email_{account_index:04d}"

            # Gerar chaves DKIM
            private_key, public_key = DKIMManager.generate_keypair()

            # Alocar IPv6 (simulado)
            ipv6 = self._allocate_ipv6(account_index)

            # Criar sub-subdomínio via deSEC
            if token:
                self._create_subdomain(main_domain, sub_name, token)

                # Configurar registos
                self._configure_ptr(main_domain, sub_name, ipv6, token)
                self._configure_spf(main_domain, sub_name, ipv6, token)
                self._publish_dkim(main_domain, sub_name, public_key, token)
                self._configure_dmarc(main_domain, sub_name, token)
            else:
                logger.warning(f"{E['warn']} Sem token para domínio {main_domain}, simulação")

            account = SenderAccount(
                id=account_id,
                email=f"alex@{full_domain}",
                domain=full_domain,
                main_domain=main_domain,
                ipv6=ipv6,
                dkim_selector="s2026",
                dkim_private_key=private_key,
                dkim_public_key=public_key,
                status="warming",
                created_at=datetime.now(timezone.utc).isoformat()
            )

            logger.info(f"{E['ok']} Conta {account_id}: {full_domain} ({ipv6})")
            return account

        except Exception as e:
            logger.error(f"{E['error']} Falha ao criar conta {account_index}: {e}")
            return None

    def _allocate_ipv6(self, idx: int) -> str:
        # Simulação
        return f"2a11:6c7:f10:5::{idx}"

    def _create_subdomain(self, main_domain: str, sub_name: str, token: str) -> bool:
        """Cria sub-subdomínio via deSEC API."""
        # Simulação com delay
        time.sleep(0.5)  # evitar rate limit
        logger.info(f"   Criando {sub_name}.{main_domain} (token: {token[:6]}...)")
        return True

    def _configure_ptr(self, main_domain: str, sub_name: str, ipv6: str, token: str) -> bool:
        time.sleep(0.3)
        return True

    def _configure_spf(self, main_domain: str, sub_name: str, ipv6: str, token: str) -> bool:
        time.sleep(0.3)
        return True

    def _publish_dkim(self, main_domain: str, sub_name: str, public_key: str, token: str) -> bool:
        time.sleep(0.3)
        return True

    def _configure_dmarc(self, main_domain: str, sub_name: str, token: str) -> bool:
        time.sleep(0.3)
        return True

    def provision_all_accounts(self, dry_run: bool = False) -> List[SenderAccount]:
        logger.info(f"{E['start']} A criar {self.num_accounts} contas distribuídas por {len(self.desec_domains)} domínios...")

        if dry_run:
            logger.info(f"{E['test']} DRY RUN: Nenhuma conta real criada.")
            # Criar contas simuladas
            accounts = []
            for i in range(self.num_accounts):
                domain_idx = i % len(self.desec_domains)
                main_domain = self.desec_domains[domain_idx]
                sub_name = f"sub{i:04d}"
                accounts.append(SenderAccount(
                    id=f"email_{i:04d}",
                    email=f"alex@{sub_name}.{main_domain}",
                    domain=f"{sub_name}.{main_domain}",
                    main_domain=main_domain,
                    ipv6=f"2a11:6c7:f10:5::{i}",
                    dkim_selector="s2026",
                    dkim_private_key="FAKE",
                    dkim_public_key="FAKE",
                    status="warming",
                    created_at=datetime.now(timezone.utc).isoformat()
                ))
            return accounts

        accounts = []
        with ThreadPoolExecutor(max_workers=min(10, len(self.desec_tokens))) as executor:
            futures = {}
            for i in range(self.num_accounts):
                future = executor.submit(self.create_account, i)
                futures[future] = i

            for future in as_completed(futures):
                try:
                    account = future.result()
                    if account:
                        accounts.append(account)
                    if len(accounts) % 100 == 0:
                        logger.info(f"{E['stats']} Progresso: {len(accounts)}/{self.num_accounts}")
                except Exception as e:
                    logger.error(f"{E['error']} Erro: {e}")

        logger.info(f"{E['ok']} Criadas {len(accounts)} contas")
        return accounts


# ============================================================================
# MUTATION ENGINE
# ============================================================================

class MutationEngine:
    SYNONYMS = {
        "Descubra": ["Saiba", "Conheça", "Veja", "Encontre", "Explore"],
        "Session Matrix": ["técnica exclusiva", "sistema proprietário", "método avançado"],
        "revolucionário": ["inovador", "transformador", "game-changer"],
        "Olá": ["Oi", "E aí", "Ei", "Olá novamente"],
        "Ver": ["Conhecer", "Explorar", "Acessar", "Descobrir"],
    }

    UNICODE_SPACES = ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f"]

    @classmethod
    def apply_mutations(cls, html: str, account_id: str, lead_email: str, day: int) -> str:
        seed = hash(f"{account_id}_{lead_email}_{day}") % 10000
        random.seed(seed)

        # Substituir sinónimos
        for word, synonyms in cls.SYNONYMS.items():
            if word in html:
                html = html.replace(word, random.choice(synonyms))

        # Elementos invisíveis
        comment = f"<!-- mutation_{random.randint(10000, 99999)} -->"
        html = html.replace("<body>", f"<body>\n{comment}")

        # Espaço Unicode
        space = random.choice(cls.UNICODE_SPACES)
        mid = len(html) // 2
        html = html[:mid] + space + html[mid:]

        # Atributo data-*
        attr = f'data-mut="{random.randint(10000, 99999)}"'
        html = html.replace("<p>", f"<p {attr}>")

        # Tracking pixel
        tracking_hash = hashlib.sha256(
            f"{account_id}_{lead_email}_{day}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        pixel = f'<img src="https://tracking.veriscope.com/pixel?lead={lead_email}&day={day}&hash={tracking_hash}" width="1" height="1" style="display:none;">'
        html = html.replace("</body>", pixel + "\n</body>")

        return html


# ============================================================================
# EMAIL TEMPLATES (5 dias, português)
# ============================================================================

class EmailTemplates:
    LOGO_SVG = """
    <svg width="120" height="40" viewBox="0 0 120 40" xmlns="http://www.w3.org/2000/svg">
        <rect width="120" height="40" rx="8" fill="#2563eb"/>
        <circle cx="25" cy="20" r="10" fill="white"/>
        <polygon points="25,28 15,35 35,35" fill="white"/>
        <text x="50" y="27" fill="white" font-size="16" font-weight="bold">Veriscope</text>
    </svg>
    """

    CSS_BASE = """
    body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .header { text-align: center; margin-bottom: 30px; }
    .logo { width: 120px; height: auto; }
    .content { font-size: 16px; line-height: 1.8; }
    .button { display: inline-block; background: #2563eb; color: #fff; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
    .button:hover { background: #1d4ed8; }
    .footer { text-align: center; font-size: 12px; color: #999; margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px; }
    """

    @staticmethod
    def get_email(day: int) -> Dict:
        templates = {
            1: EmailTemplates._email_1(),
            2: EmailTemplates._email_2(),
            3: EmailTemplates._email_3(),
            4: EmailTemplates._email_4(),
            5: EmailTemplates._email_5(),
        }
        return templates.get(day, templates[1])

    @staticmethod
    def _email_1() -> Dict:
        return {
            "day": 1,
            "subject": "[1/5] Posso mostrar-te algo amanhã?",
            "button_text": "Ver a ideia",
            "button_url": "https://veriscope-com-session-matrix.pages.dev/",
            "html": f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email 1</title>
            <style>{EmailTemplates.CSS_BASE}</style></head>
            <body><div class="container">
            <div class="header">{EmailTemplates.LOGO_SVG}</div>
            <div class="content">
            <p>Olá,</p>
            <p>Se já estás há alguns anos no trading, provavelmente já viste isto acontecer:</p>
            <p>Um trader perde uma operação e a primeira pergunta que faz é:</p>
            <p><strong>"O que está a faltar no meu gráfico?"</strong></p>
            <p>Depois adiciona mais uma confirmação. Mais um indicador. Mais uma linha.</p>
            <p>Mas existe uma pergunta que quase ninguém faz:</p>
            <p><strong>E se o problema não for falta de informação?</strong></p>
            <p>Nós começámos a pensar nisso há algum tempo.</p>
            <p>Amanhã vou mostrar-te uma ferramenta que nasceu precisamente dessa pergunta.</p>
            <p>Chama-se <strong>Veriscope Session Matrix</strong>.</p>
            <p style="text-align:center;"><a href="https://veriscope-com-session-matrix.pages.dev/" class="button">Ver a ideia</a></p>
            <p>Até amanhã.</p>
            <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div class="footer"><p>&copy; 2026 Veriscope. Todos os direitos reservados.</p></div>
            </div></body></html>
            """
        }

    @staticmethod
    def _email_2() -> Dict:
        return {
            "day": 2,
            "subject": "[2/5] A pergunta que levou ao Session Matrix",
            "button_text": "Ver o Session Matrix",
            "button_url": "https://veriscope-com-session-matrix.pages.dev/",
            "html": f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email 2</title>
            <style>{EmailTemplates.CSS_BASE}</style></head>
            <body><div class="container">
            <div class="header">{EmailTemplates.LOGO_SVG}</div>
            <div class="content">
            <p>Olá,</p>
            <p>Ontem falei-te de uma pergunta:</p>
            <p><strong>E se o problema não for falta de informação?</strong></p>
            <p>Essa pergunta levou-nos a olhar para o trading de outra forma.</p>
            <p>Muitos traders passam horas à frente do gráfico. Esperam. Analisam.</p>
            <p>E quando o mercado faz algo importante, o movimento já passou.</p>
            <p>Não porque não sabiam analisar. Mas porque estavam a tentar dar atenção a tudo.</p>
            <p>Foi daí que nasceu o <strong>Veriscope Session Matrix</strong>.</p>
            <p>Ele não te diz quando comprar. Não te diz quando vender.</p>
            <p>A pergunta que ele ajuda a responder é:</p>
            <p><strong>Quando é que vale a pena olhar com mais atenção?</strong></p>
            <p style="text-align:center;"><a href="https://veriscope-com-session-matrix.pages.dev/" class="button">Ver o Session Matrix</a></p>
            <p>Até amanhã.</p>
            <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div class="footer"><p>&copy; 2026 Veriscope. Todos os direitos reservados.</p></div>
            </div></body></html>
            """
        }

    @staticmethod
    def _email_3() -> Dict:
        return {
            "day": 3,
            "subject": "[3/5] Saber quando olhar resolveu só metade",
            "button_text": "Ver o Veriscope Prime",
            "button_url": "https://veriscope-com-session-matrix-access.pages.dev/",
            "html": f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email 3</title>
            <style>{EmailTemplates.CSS_BASE}</style></head>
            <body><div class="container">
            <div class="header">{EmailTemplates.LOGO_SVG}</div>
            <div class="content">
            <p>Olá,</p>
            <p>Ontem entreguei-te o Veriscope Session Matrix.</p>
            <p>Mas quando sabes quando prestar atenção, outra pergunta aparece:</p>
            <p><strong>"O que é que estou realmente a olhar?"</strong></p>
            <p>Imagina que chegas ao gráfico no momento certo. Tens estrutura, liquidez, zonas.</p>
            <p>O problema não é não saberes o que são essas coisas. O problema é:</p>
            <p><strong>Quanto trabalho precisas de fazer para juntar tudo outra vez?</strong></p>
            <p>Foi assim que nasceu o <strong>Veriscope Prime</strong>.</p>
            <p>Não é uma máquina de sinais. Ajuda-te a organizar o contexto que já existe.</p>
            <p style="text-align:center;"><a href="https://veriscope-com-session-matrix-access.pages.dev/" class="button">Ver o Veriscope Prime</a></p>
            <p>Até amanhã.</p>
            <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div class="footer"><p>&copy; 2026 Veriscope. Todos os direitos reservados.</p></div>
            </div></body></html>
            """
        }

    @staticmethod
    def _email_4() -> Dict:
        return {
            "day": 4,
            "subject": "[4/5] O gráfico é só uma parte",
            "button_text": "Conhecer o Veriscope Edge",
            "button_url": "https://veriscope-com-session-matrix-access.pages.dev/",
            "html": f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email 4</title>
            <style>{EmailTemplates.CSS_BASE}</style></head>
            <body><div class="container">
            <div class="header">{EmailTemplates.LOGO_SVG}</div>
            <div class="content">
            <p>Olá,</p>
            <p>Durante estes dias falámos sobre duas perguntas.</p>
            <p><strong>Quando vale a pena prestar atenção?</strong></p>
            <p><strong>O que é que realmente importa quando estás a olhar?</strong></p>
            <p>Mas existe uma terceira parte que não aparece no gráfico.</p>
            <p>O que acontece à volta de uma operação: risco, tamanho da posição, drawdown, planeamento.</p>
            <p>Foi por isso que criámos o <strong>Veriscope Edge</strong>.</p>
            <p>É um espaço de trabalho com 19 ferramentas para organizar o processo de trading.</p>
            <p style="text-align:center;"><a href="https://veriscope-com-session-matrix-access.pages.dev/" class="button">Conhecer o Veriscope Edge</a></p>
            <p>Até amanhã.</p>
            <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div class="footer"><p>&copy; 2026 Veriscope. Todos os direitos reservados.</p></div>
            </div></body></html>
            """
        }

    @staticmethod
    def _email_5() -> Dict:
        return {
            "day": 5,
            "subject": "[5/5] Agora já conheces o quadro completo",
            "button_text": "Conhecer o Veriscope",
            "button_url": "https://veriscope-com-prime.pages.dev/",
            "html": f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Email 5</title>
            <style>{EmailTemplates.CSS_BASE}</style></head>
            <body><div class="container">
            <div class="header">{EmailTemplates.LOGO_SVG}</div>
            <div class="content">
            <p>Olá,</p>
            <p>Há cinco dias, comecei com uma pergunta:</p>
            <p><strong>E se o problema não for falta de informação?</strong></p>
            <p>Depois falámos sobre:</p>
            <p><strong>Session Matrix</strong> → Quando prestar atenção.</p>
            <p><strong>Prime</strong> → O que estás a olhar.</p>
            <p><strong>Edge</strong> → Como organizas o processo.</p>
            <p>O Veriscope está oficialmente em lançamento.</p>
            <p style="text-align:center;"><a href="https://veriscope-com-prime.pages.dev/" class="button">Conhecer o Veriscope</a></p>
            <p>Não precisas de mudar a tua estratégia. Apenas queríamos mostrar-te uma forma diferente de olhar para o processo.</p>
            <p>Obrigado por acompanhares estes cinco dias.</p>
            <p>Alex<br><strong>Liquidity Alert</strong></p>
            </div>
            <div class="footer"><p>&copy; 2026 Veriscope. Todos os direitos reservados.</p></div>
            </div></body></html>
            """
        }


# ============================================================================
# IDEMPOTENCY MANAGER
# ============================================================================

class IdempotencyManager:
    def __init__(self):
        self.sent: Set[str] = set()
        self._load()

    def _load(self):
        if IDEMPOTENCY_PATH.exists():
            try:
                df = pd.read_parquet(IDEMPOTENCY_PATH)
                self.sent = set(df["key"].tolist())
                logger.info(f"{E['ok']} Carregados {len(self.sent)} registos de idempotência")
            except Exception as e:
                logger.warning(f"{E['warn']} Erro ao carregar idempotência: {e}")

    def save(self):
        try:
            df = pd.DataFrame({"key": list(self.sent)})
            df.to_parquet(IDEMPOTENCY_PATH, index=False)
        except Exception as e:
            logger.error(f"{E['error']} Erro ao salvar idempotência: {e}")

    def is_sent(self, email: str, account_id: str, day: int) -> bool:
        key = hashlib.sha256(f"{email}_{account_id}_{day}".encode()).hexdigest()
        return key in self.sent

    def mark_sent(self, email: str, account_id: str, day: int):
        key = hashlib.sha256(f"{email}_{account_id}_{day}".encode()).hexdigest()
        self.sent.add(key)


# ============================================================================
# HF DATA LOADER
# ============================================================================

class HFDataLoader:
    def __init__(self):
        self.token = config.hf_token
        self.repo_emails = config.hf_repo_emails
        self.repo_checkpoint = config.hf_repo_checkpoint
        self.api = HfApi()

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def list_domains(self) -> List[str]:
        try:
            files = self.api.list_repo_files(
                repo_id=self.repo_emails,
                token=self.token,
                repo_type="dataset"
            )
            domains = set()
            for f in files:
                if f.startswith("Trader_Emails/") and "/" in f:
                    parts = f.split("/")
                    if len(parts) >= 2:
                        domains.add(parts[1])
            return sorted(list(domains))
        except Exception as e:
            logger.error(f"{E['error']} Erro ao listar domínios: {e}")
            return []

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def load_leads_for_domain(self, domain: str, batch_num: int = 1) -> List[Dict]:
        try:
            filename = f"Trader_Emails/{domain}/{domain}_batch_{batch_num}.parquet"
            file_path = hf_hub_download(
                repo_id=self.repo_emails,
                filename=filename,
                token=self.token,
                repo_type="dataset"
            )
            df = pd.read_parquet(file_path)
            leads = df.to_dict('records')
            logger.info(f"{E['download']} Carregados {len(leads)} leads de {domain} (batch {batch_num})")
            return leads
        except Exception as e:
            logger.warning(f"{E['warn']} Erro ao carregar {domain} batch {batch_num}: {e}")
            return []

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def load_sender_accounts(self) -> List[SenderAccount]:
        try:
            file_path = hf_hub_download(
                repo_id=self.repo_checkpoint,
                filename="sender_accounts.json",
                token=self.token,
                repo_type="dataset"
            )
            with open(file_path, 'r') as f:
                data = json.load(f)
            accounts = [SenderAccount(**acc) for acc in data]
            logger.info(f"{E['ok']} Carregadas {len(accounts)} contas do HF")
            return accounts
        except Exception as e:
            logger.warning(f"{E['warn']} Erro ao carregar contas: {e}")
            return []

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def save_sender_accounts(self, accounts: List[SenderAccount]):
        try:
            data = [asdict(acc) for acc in accounts]
            with open(ACCOUNTS_PATH, 'w') as f:
                json.dump(data, f, indent=2)
            self.api.upload_file(
                path_or_fileobj=str(ACCOUNTS_PATH),
                path_in_repo="sender_accounts.json",
                repo_id=self.repo_checkpoint,
                repo_type="dataset",
                token=self.token
            )
            logger.info(f"{E['ok']} {len(accounts)} contas salvas no HF")
        except Exception as e:
            logger.error(f"{E['error']} Erro ao salvar contas: {e}")

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def save_campaign_state(self, state: CampaignState):
        try:
            state_data = asdict(state)
            state_json = json.dumps(state_data, default=str)
            state_hash = hashlib.sha256(state_json.encode()).hexdigest()
            state_data["hash_sha256"] = state_hash

            with open(STATE_PATH, 'w') as f:
                json.dump(state_data, f, indent=2, default=str)

            self.api.upload_file(
                path_or_fileobj=str(STATE_PATH),
                path_in_repo="send_state.json",
                repo_id=self.repo_checkpoint,
                repo_type="dataset",
                token=self.token
            )
            logger.info(f"{E['ok']} Estado salvo no HF (hash: {state_hash[:8]}...)")
        except Exception as e:
            logger.error(f"{E['error']} Erro ao salvar estado: {e}")

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def load_campaign_state(self) -> Optional[CampaignState]:
        try:
            file_path = hf_hub_download(
                repo_id=self.repo_checkpoint,
                filename="send_state.json",
                token=self.token,
                repo_type="dataset"
            )
            with open(file_path, 'r') as f:
                data = json.load(f)
            return CampaignState(**data)
        except Exception as e:
            logger.info(f"{E['info']} Sem estado anterior: {e}")
            return None


# ============================================================================
# SMTP SENDER
# ============================================================================

class SMTPSender:
    def __init__(self, account: SenderAccount):
        self.account = account
        self.host = config.kumomta_host
        self.port = config.kumomta_port
        self.timeout = 30

    async def send_email(self, to_email: str, subject: str, html_body: str) -> Tuple[bool, str]:
        try:
            try:
                validate_email(to_email)
            except EmailNotValidError as e:
                logger.warning(f"{E['warn']} Email inválido: {to_email} - {e}")
                return False, "400 Invalid email"

            msg = MIMEMultipart('alternative')
            msg['From'] = f"{config.from_name} <{self.account.email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Reply-To'] = self.account.email
            msg['Date'] = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
            msg['Message-ID'] = f"<{hashlib.sha256(f'{to_email}{datetime.now().isoformat()}'.encode()).hexdigest()}@{self.account.domain}>"

            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)

            message_bytes = msg.as_bytes()
            if self.account.dkim_private_key:
                message_bytes = DKIMManager.sign_message(
                    message_bytes,
                    self.account.dkim_private_key,
                    self.account.domain,
                    self.account.dkim_selector
                )

            formatted_host = f"[{self.host}]" if ':' in self.host else self.host

            async with aiosmtplib.SMTP(
                hostname=formatted_host,
                port=self.port,
                timeout=self.timeout,
                use_tls=False
            ) as smtp:
                await smtp.ehlo()
                await smtp.sendmail(self.account.email, [to_email], message_bytes)

            logger.debug(f"{E['ok']} Email enviado para {to_email} de {self.account.email}")
            return True, "250 OK"

        except aiosmtplib.SMTPException as e:
            error_str = str(e)
            if error_str.startswith("4"):
                return False, "4xx Throttle"
            elif error_str.startswith("5"):
                return False, "5xx Reject"
            else:
                return False, f"SMTP Error: {error_str[:50]}"

        except Exception as e:
            logger.error(f"{E['error']} Erro ao enviar para {to_email}: {e}")
            return False, f"Exception: {type(e).__name__}"


# ============================================================================
# BATCH PROCESSOR
# ============================================================================

class BatchProcessor:
    def __init__(self, day: int, runner_id: int, total_runners: int, is_test: bool = False):
        self.day = day
        self.runner_id = runner_id
        self.total_runners = total_runners
        self.is_test = is_test
        self.idempotency = IdempotencyManager()
        self.hf_loader = HFDataLoader()
        self.template = EmailTemplates.get_email(day)

    async def process_batch(self, leads: List[Dict], accounts: List[SenderAccount]) -> Dict:
        stats = {
            "sent": 0,
            "throttled": 0,
            "rejected": 0,
            "failed": 0,
            "skipped_duplicate": 0
        }

        runner_leads = self._distribute_leads(leads)

        for idx, lead in enumerate(runner_leads):
            if self.idempotency.is_sent(lead["email"], "runner", self.day):
                stats["skipped_duplicate"] += 1
                continue

            account = accounts[idx % len(accounts)]

            html = MutationEngine.apply_mutations(
                self.template["html"],
                account.id,
                lead["email"],
                self.day
            )

            sender = SMTPSender(account)
            success, code = await sender.send_email(
                lead["email"],
                self.template["subject"],
                html
            )

            if success:
                stats["sent"] += 1
                self.idempotency.mark_sent(lead["email"], account.id, self.day)
                domain = lead.get("domain", "unknown")
                account.daily_sent[domain] = account.daily_sent.get(domain, 0) + 1
                account.total_sent += 1
            elif "4xx" in code:
                stats["throttled"] += 1
            elif "5xx" in code:
                stats["rejected"] += 1
            else:
                stats["failed"] += 1

            if (idx + 1) % 100 == 0:
                logger.info(f"{E['stats']} Runner {self.runner_id}: {idx+1}/{len(runner_leads)} processados")

            if (idx + 1) % 5000 == 0:
                self.idempotency.save()
                self.hf_loader.save_sender_accounts(accounts)

        self.idempotency.save()
        return stats

    def _distribute_leads(self, leads: List[Dict]) -> List[Dict]:
        if self.is_test:
            return leads  # modo teste: todos os runners enviam para os mesmos emails
        total = len(leads)
        per_runner = total // self.total_runners
        start = (self.runner_id - 1) * per_runner
        end = start + per_runner if self.runner_id < self.total_runners else total
        return leads[start:end]


# ============================================================================
# CAMPAIGN ORCHESTRATOR
# ============================================================================

class CampaignOrchestrator:
    def __init__(self, day: int, runner_id: int, total_runners: int, dataset_source: str = "hf"):
        self.day = day
        self.runner_id = runner_id
        self.total_runners = total_runners
        self.dataset_source = dataset_source
        self.is_test = (dataset_source == "env")

        self.hf_loader = HFDataLoader()
        self.state_manager = StateManager()

        self.shutdown_requested = False
        self.start_time = datetime.now()

    async def run(self):
        logger.info(f"{E['start']} ===== INÍCIO DA CAMPANHA =====")
        logger.info(f"Dia: {self.day}, Runner: {self.runner_id}/{self.total_runners}")
        logger.info(f"Fonte: {'TESTE' if self.is_test else 'PRODUÇÃO'}")

        state = self.state_manager.load_or_create(self.day)
        if state.status == "COMPLETED":
            logger.info(f"{E['completed']} Campanha já concluída!")
            return

        accounts = self.hf_loader.load_sender_accounts()
        if not accounts:
            logger.error(f"{E['error']} Nenhuma conta carregada. Execute o provisionamento primeiro.")
            return

        logger.info(f"{E['accounts']} {len(accounts)} contas carregadas")

        if self.is_test:
            leads = self._get_test_leads()
        else:
            leads = await self._load_production_leads(state)

        if not leads:
            logger.error(f"{E['error']} Nenhum lead carregado")
            return

        logger.info(f"{E['list']} {len(leads)} leads para processar")

        processor = BatchProcessor(self.day, self.runner_id, self.total_runners, self.is_test)
        stats = await processor.process_batch(leads, accounts)

        state.total_sent_global += stats["sent"]
        state.total_sent_this_session += stats["sent"]
        state.last_checkpoint = datetime.now(timezone.utc).isoformat()

        if state.total_sent_global >= config.emails_per_day:
            state.status = "COMPLETED"
            logger.info(f"{E['completed']} 🎉 META ATINGIDA! {state.total_sent_global:,} emails enviados")
        else:
            state.status = "RUNNING"

        self.state_manager.save(state)

        logger.info(f"{E['stats']} ===== RESUMO =====")
        logger.info(f"Enviados: {stats['sent']:,}")
        logger.info(f"Throttled: {stats['throttled']:,}")
        logger.info(f"Rejeitados: {stats['rejected']:,}")
        logger.info(f"Falhas: {stats['failed']:,}")
        logger.info(f"Duplicados ignorados: {stats['skipped_duplicate']:,}")
        logger.info(f"Total global: {state.total_sent_global:,}")

        if self.shutdown_requested and state.status != "COMPLETED":
            logger.info(f"{E['shutdown']} Shutdown planeado. A próxima sessão continuará.")

    def _get_test_leads(self) -> List[Dict]:
        """Usa os emails de teste fixos."""
        return [
            {"email": email, "domain": email.split('@')[1]}
            for email in config.test_emails
            if email
        ]

    async def _load_production_leads(self, state: CampaignState) -> List[Dict]:
        domains = self.hf_loader.list_domains()
        if not domains:
            domains = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com"]

        start_idx = 0
        if state.current_domain in domains:
            start_idx = domains.index(state.current_domain)

        all_leads = []
        for domain in domains[start_idx:]:
            if domain in state.completed_domains:
                continue

            deficit_key = f"{self.day}_{domain}"
            deficit = state.pending_completion.get(deficit_key, 0)

            leads = self.hf_loader.load_leads_for_domain(domain, batch_num=1)

            if leads:
                if deficit > 0:
                    extra = min(deficit, len(leads))
                    leads = leads[:extra] + leads
                    state.pending_completion[deficit_key] = deficit - extra
                    if state.pending_completion[deficit_key] <= 0:
                        del state.pending_completion[deficit_key]

                all_leads.extend(leads)
                state.current_domain = domain

                if len(all_leads) >= 10000:
                    break

        return all_leads


# ============================================================================
# STATE MANAGER
# ============================================================================

class StateManager:
    def __init__(self):
        self.hf_loader = HFDataLoader()

    def load_or_create(self, day: int) -> CampaignState:
        state = self.hf_loader.load_campaign_state()
        if state and state.current_day == day:
            logger.info(f"{E['recover']} Estado recuperado: {state.total_sent_global:,} emails enviados")
            return state

        logger.info(f"{E['ok']} Criando novo estado para o dia {day}")
        return CampaignState(
            status="RUNNING",
            session_number=1,
            current_day=day,
            current_account_index=0,
            current_domain="",
            total_sent_global=0,
            total_sent_this_session=0,
            runs_without_progress=0,
            last_checkpoint=datetime.now(timezone.utc).isoformat(),
            completed_domains=[],
            pending_completion={}
        )

    def save(self, state: CampaignState):
        self.hf_loader.save_campaign_state(state)


# ============================================================================
# SHUTDOWN HANDLER
# ============================================================================

class ShutdownHandler:
    def __init__(self):
        self.shutdown_requested = False
        self.start_time = datetime.now()
        self.shutdown_minutes = config.shutdown_minutes
        self.graceful_wait = config.graceful_wait_seconds

    def check_and_shutdown(self, orchestrator: CampaignOrchestrator) -> bool:
        elapsed = (datetime.now() - self.start_time).total_seconds() / 60
        if elapsed >= self.shutdown_minutes and not self.shutdown_requested:
            logger.info(f"{E['shutdown']} ⏰ TEMPO ESGOTADO ({self.shutdown_minutes}min)")
            logger.info(f"{E['shutdown']} Iniciando shutdown planeado...")
            self.shutdown_requested = True
            orchestrator.shutdown_requested = True
            return True
        return False

    def dispatch_next_run(self):
        try:
            repo = os.getenv("GITHUB_REPOSITORY")
            if not repo:
                logger.warning(f"{E['warn']} GITHUB_REPOSITORY não definido.")
                return
            token = os.getenv("GITHUB_TOKEN")
            if not token:
                logger.warning(f"{E['warn']} GITHUB_TOKEN não definido.")
                return

            url = f"https://api.github.com/repos/{repo}/actions/workflows/sender.yml/dispatches"
            response = requests.post(
                url,
                json={"ref": "main", "inputs": {"resume": "true"}},
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            if response.status_code == 204:
                logger.info(f"{E['dispatch']} 🚀 Nova execução disparada com sucesso!")
            else:
                logger.error(f"{E['error']} Falha ao disparar: {response.status_code}")
        except Exception as e:
            logger.error(f"{E['error']} Erro ao disparar: {e}")


# ============================================================================
# MAIN
# ============================================================================

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Veriscope Email Engine v3.0")
    parser.add_argument("--dataset-source", choices=["env", "hf"], default="hf",
                       help="'env' para teste (5 emails fixos) | 'hf' para produção")
    parser.add_argument("--day", type=int, default=1, help="Dia da campanha (1-5)")
    parser.add_argument("--runner-id", type=int, default=1, help="ID do runner")
    parser.add_argument("--total-runners", type=int, default=20, help="Total de runners")
    parser.add_argument("--provision", action="store_true", help="Cria 3000 contas")
    parser.add_argument("--dry-run", action="store_true", help="Simulação")

    args = parser.parse_args()

    if args.provision:
        logger.info(f"{E['start']} ===== PROVISIONAMENTO =====")
        provisioner = ProvisioningManager()
        accounts = provisioner.provision_all_accounts(args.dry_run)
        if accounts:
            hf_loader = HFDataLoader()
            hf_loader.save_sender_accounts(accounts)
            logger.info(f"{E['ok']} {len(accounts)} contas criadas e salvas no HF")
        return

    logger.info(f"{E['start']} ===== VERISCOPE EMAIL ENGINE v3.0 =====")

    if args.dataset_source == "env" and not config.test_emails:
        logger.error(f"{E['error']} Nenhum email de teste configurado.")
        return

    orchestrator = CampaignOrchestrator(
        day=args.day,
        runner_id=args.runner_id,
        total_runners=args.total_runners,
        dataset_source=args.dataset_source
    )

    shutdown = ShutdownHandler()

    def signal_handler(sig, frame):
        logger.warning(f"{E['warn']} Sinal {sig} recebido. Iniciando shutdown...")
        orchestrator.shutdown_requested = True
        shutdown.shutdown_requested = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await orchestrator.run()
    except Exception as e:
        logger.error(f"{E['error']} Erro: {e}")
        raise

    if shutdown.shutdown_requested:
        logger.info(f"{E['shutdown']} Shutdown concluído.")
        shutdown.dispatch_next_run()

    logger.info(f"{E['completed']} ===== FIM =====")


if __name__ == "__main__":
    asyncio.run(main())
