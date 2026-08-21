#!/usr/bin/env python3
"""
VERISCOPE EMAIL MARKETING ENGINE - Corrigido (final)

Correções aplicadas:
 - DKIM real via dkimpy
 - IPv6 fallback ajustado: em dry-run usa endereço de documentação; em produção
   falha a criação da conta quando não é possível alocar IPv6
 - aiosmtplib usado com `async with` (context manager)
 - Idempotency persistente
 - Validação de e-mails com email_validator
 - Retry aumentado para downloads HF, rate limiting básico para APIs
 - Logs menos verbosos (a cada 1000 mensagens)
"""

from __future__ import annotations

import os
import sys
import json
import time
import argparse
import logging
import hashlib
import random
import threading
import asyncio
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64

# Third-party imports
try:
    import pandas as pd
    import aiosmtplib
    from huggingface_hub import HfApi, hf_hub_download
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import requests
    from tenacity import retry, stop_after_attempt, wait_exponential
    import dkim
    from email_validator import validate_email, EmailNotValidError
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Run: pip install -r requirements.txt (includes dkimpy and email-validator)")
    sys.exit(1)

# ===== CONFIGURATION =====

SAVE_PATH = Path(os.environ.get("SAVE_PATH", "./data"))
SAVE_PATH.mkdir(parents=True, exist_ok=True)

LOG_PATH = SAVE_PATH / "veriscope.log"
STATE_PATH = SAVE_PATH / "campaign_state.json"
ACCOUNTS_PATH = SAVE_PATH / "sender_accounts.json"
IDEMPOTENCY_PATH = SAVE_PATH / "idempotency.json"

# ===== COLORS & EMOJIS =====

E = {
    "start": "🚀", "download": "📥", "extract": "📦", "stats": "📊",
    "space": "💾", "email": "📧", "upload": "📤", "clean": "🧹",
    "warn": "⚠️", "error": "❌", "ok": "✅", "info": "ℹ️",
    "cpu": "⚙️", "clock": "⏱️", "list": "📋", "db": "🗄️",
    "monitor": "📡", "limit": "🛑", "debug": "🔍", "valid": "✓",
    "folder": "📁", "check": "✔️", "recover": "🔄", "save": "💾",
    "test": "🧪", "test_ok": "✅", "prod": "🏭", "smtp": "📮",
    "account": "👤", "accounts": "👥", "lock": "🔒", "unlock": "🔓",
}

# ===== LOGGING SETUP =====

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

# ===== DATACLASSES =====

@dataclass
class VeriscopeAccount:
    id: str
    address: str
    ipv6: str
    dkim_selector: str
    dkim_private_key: str
    dkim_public_key: str
    status: str
    daily_quota: int
    daily_sent_today: int
    total_sent: int
    created_at: str
    first_use: Optional[str] = None
    last_use: Optional[str] = None
    reputation_score: float = 100.0

@dataclass
class EmailResult:
    lead_email: str
    account_id: str
    domain: str
    day: int
    status: str
    smtp_code: str
    message: str
    timestamp: str

@dataclass
class CampaignState:
    status: str
    current_day: int
    current_email_number: int
    current_account_index: int
    current_domain: str
    total_sent_today: int
    total_sent_campaign: int
    last_checkpoint: str
    hash_sha256: str
    completed_domains: List[str]
    pending_completion: Dict[str, int]
    session_number: int

# ===== ENVIRONMENT LOADING =====

class ConfigLoader:
    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN")
        self.route64_key = os.getenv("ROUTE64_API_KEY")
        self.desec_tokens = self._load_desec_tokens()
        self.kumomta_host = os.getenv("KUMOMTA_HOST", "2a11:6c7:f10:5::1")
        self.kumomta_port = int(os.getenv("KUMOMTA_PORT", "2525"))
        self.desec_domain = os.getenv("DESEC_DOMAIN", "oeudominio.dedyn.io")
        self.test_email_gmail = os.getenv("TEST_EMAIL_GMAIL")
        self.test_email_outlook = os.getenv("TEST_EMAIL_OUTLOOK")
        self.test_email_protonmail = os.getenv("TEST_EMAIL_PROTONMAIL")
        self.test_email_hotmail = os.getenv("TEST_EMAIL_HOTMAIL")
        self.campaign_from_name = os.getenv("CAMPAIGN_FROM_NAME", "Alex | Liquidity Alert")
        self.email_subjects = {
            1: os.getenv("EMAIL_SUBJECT_1", "[1/5] Posso mostrar-te algo amanhã?"),
            2: os.getenv("EMAIL_SUBJECT_2", "[2/5] A pergunta que levou ao Session Matrix"),
            3: os.getenv("EMAIL_SUBJECT_3", "[3/5] Saber quando olhar resolveu só metade"),
            4: os.getenv("EMAIL_SUBJECT_4", "[4/5] O gráfico é só uma parte"),
            5: os.getenv("EMAIL_SUBJECT_5", "[5/5] Agora já conheces o quadro completo"),
        }
        self.button_urls = {
            1: os.getenv("BUTTON_URL_1"),
            2: os.getenv("BUTTON_URL_2"),
            3: os.getenv("BUTTON_URL_3"),
            4: os.getenv("BUTTON_URL_4"),
            5: os.getenv("BUTTON_URL_5"),
        }
        logger.info(f"{E['ok']} Configuration loaded")
        self._validate()

    def _load_desec_tokens(self) -> List[str]:
        tokens = []
        for i in range(1, 27):
            t = os.getenv(f"DESEC_TOKEN_{i}")
            if t:
                tokens.append(t)
        logger.info(f"{E['ok']} Loaded {len(tokens)} deSEC tokens")
        return tokens

    def _validate(self):
        if not self.hf_token:
            logger.warning(f"{E['warn']} HF_TOKEN not set; HF operations disabled")
        if not self.kumomta_host:
            raise ValueError("KUMOMTA_HOST not set")
        if not self.desec_tokens:
            logger.warning(f"{E['warn']} No deSEC tokens found; provisioning disabled")
        logger.info(f"{E['check']} Config validation complete")

config = ConfigLoader()

# ===== DKIM HELPER =====

class DKIMManager:
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        public_pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        return private_pem, public_pem

    @staticmethod
    def sign_message(raw_message_bytes: bytes, selector: str, domain: str, private_key_pem: str, include_headers=None) -> bytes:
        if include_headers is None:
            include_headers = [b"from", b"to", b"subject", b"date", b"message-id"]
        try:
            sig = dkim.sign(message=raw_message_bytes,
                            selector=selector.encode('utf-8'),
                            domain=domain.encode('utf-8'),
                            privkey=private_key_pem.encode('utf-8'),
                            include_headers=include_headers)
            return sig
        except Exception as e:
            logger.error(f"{E['error']} DKIM signing failed: {e}")
            raise

# ===== MUTATION ENGINE =====

class MutationEngine:
    HTML_COMMENTS = ["<!-- session_matrix_v1 -->", "<!-- veriscope_tracking -->", "<!-- content_delivery_1 -->"]
    UNICODE_SPACES = ["\u200b", "\u200c", "\u200d"]

    @staticmethod
    def apply_mutations(html: str, seed: int) -> str:
        random.seed(seed)
        comment = random.choice(MutationEngine.HTML_COMMENTS)
        html = html.replace("<body>", f"<body>\n{comment}", 1)
        mid = len(html) // 2
        html = html[:mid] + random.choice(MutationEngine.UNICODE_SPACES) + html[mid:]
        attr = f'data-mutation="{secrets.token_hex(8)}"'
        html = html.replace("<p>", f"<p {attr}>", 1)
        return html

    @staticmethod
    def generate_tracking_hash(account_id: str, lead_email: str, day: int) -> str:
        seed_str = f"{account_id}:{lead_email}:{day}:{datetime.now().isoformat()}"
        return hashlib.sha256(seed_str.encode()).hexdigest()

# ===== EMAIL TEMPLATES =====

VERISCOPE_LOGO_SVG = '<svg width="200" height="50" xmlns="http://www.w3.org/2000/svg"><text x="10" y="35" font-family="Arial" font-size="28" fill="#1a73e8">Veriscope</text></svg>'

class EmailTemplateGenerator:
    def __init__(self, day: int, account_id: str):
        self.day = day
        self.account_id = account_id

    def get_subject(self) -> str:
        return config.email_subjects.get(self.day, "Veriscope Update")

    def get_html_body(self, lead_email: str, lead_name: str = "") -> str:
        button_url = config.button_urls.get(self.day, "#")
        tracking_hash = MutationEngine.generate_tracking_hash(self.account_id, lead_email, self.day)
        logo_b64 = base64.b64encode(VERISCOPE_LOGO_SVG.encode()).decode()
        day_content = f"<p>Conteúdo dia {self.day}</p>"
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{self.get_subject()}</title></head><body><div class="container"><div class="logo"><img src="data:image/svg+xml;base64,{logo_b64}" alt="Veriscope"></div><h2>{self.get_subject()}</h2>{day_content}<div style="text-align:center;"><a href="{button_url}?lead_id={lead_email}&hash={tracking_hash}">Call to action</a></div><div class="signature"><p>Alex<br>Liquidity Alert</p></div><img src="https://tracking.veriscope.com/pixel?lead_id={lead_email}&email={self.day}&hash={tracking_hash}" width="1" height="1" alt=""></div></body></html>"""
        seed = int(hashlib.md5(self.account_id.encode()).hexdigest(), 16)
        return MutationEngine.apply_mutations(html, seed)

    def get_text_body(self) -> str:
        return f"{self.get_subject()}\n\nAlex | Liquidity Alert\n\n{config.button_urls.get(self.day, '#')}\n\nVeriscope © 2026"

# ===== HUGGINGFACE INTEGRATION =====

class HFDataLoader:
    def __init__(self):
        self.api = HfApi()
        self.hf_token = config.hf_token

    @retry(stop=stop_after_attempt(15), wait=wait_exponential(multiplier=2, min=4, max=60))
    def _download_file(self, repo_id: str, filename: str) -> str:
        if not self.hf_token:
            raise RuntimeError("HF_TOKEN not configured")
        return hf_hub_download(repo_id=repo_id, filename=filename, token=self.hf_token)

    def load_leads_batch_generator(self, batch_size: int = 100000, dataset_source: str = "hf"):
        if dataset_source == "env":
            leads = []
            if config.test_email_gmail:
                leads.append({"email": config.test_email_gmail, "domain": "gmail.com", "name": "Teste Gmail"})
            if config.test_email_outlook:
                leads.append({"email": config.test_email_outlook, "domain": "outlook.com", "name": "Teste Outlook"})
            if config.test_email_protonmail:
                leads.append({"email": config.test_email_protonmail, "domain": "protonmail.com", "name": "Teste ProtonMail"})
            if config.test_email_hotmail:
                leads.append({"email": config.test_email_hotmail, "domain": "hotmail.com", "name": "Teste Hotmail"})
            logger.info(f"{E['test']} TEST MODE: Loaded {len(leads)} leads from env")
            yield leads
            return

        domains = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "protonmail.com"]
        batch = []
        for domain in domains:
            try:
                file_path = self._download_file(repo_id="Valter3B/Trader_Emails", filename=f"Trader_Emails/{domain}/{domain}_batch_1.parquet")
                df = pd.read_parquet(file_path)
                for _, row in df.iterrows():
                    batch.append({"email": row["email"], "domain": domain, "name": row.get("name", "Lead")})
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
            except Exception as e:
                logger.warning(f"{E['warn']} Failed to load {domain}: {e}")
                continue
        if batch:
            yield batch

    def load_sender_accounts(self) -> List[VeriscopeAccount]:
        try:
            if not self.hf_token:
                logger.warning(f"{E['warn']} HF_TOKEN missing; cannot load accounts from HuggingFace")
                return []
            file_path = self._download_file(repo_id="Valter3B/minerador_checkpoints", filename="sender_accounts.json")
            with open(file_path, 'r', encoding='utf-8') as f:
                accounts_data = json.load(f)
            accounts = [VeriscopeAccount(**acc) for acc in accounts_data]
            logger.info(f"{E['ok']} Loaded {len(accounts)} accounts from HuggingFace")
            return accounts
        except Exception as e:
            logger.error(f"{E['error']} Failed to load accounts: {e}")
            return []

    def save_sender_accounts(self, accounts: List[VeriscopeAccount]):
        try:
            accounts_data = [asdict(acc) for acc in accounts]
            with open(ACCOUNTS_PATH, 'w', encoding='utf-8') as f:
                json.dump(accounts_data, f, indent=2)
            if self.hf_token:
                self.api.upload_file(path_or_fileobj=str(ACCOUNTS_PATH),
                                     path_in_repo="sender_accounts.json",
                                     repo_id="Valter3B/minerador_checkpoints",
                                     repo_type="dataset",
                                     token=self.hf_token)
            logger.info(f"{E['ok']} Saved {len(accounts)} accounts (local and HF if token present)")
        except Exception as e:
            logger.error(f"{E['error']} Failed to save accounts: {e}")

    def save_campaign_state(self, state: CampaignState):
        try:
            state_data = asdict(state)
            state_json = json.dumps(state_data)
            state_hash = hashlib.sha256(state_json.encode()).hexdigest()
            state_data["hash_sha256"] = state_hash
            with open(STATE_PATH, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2)
            if self.hf_token:
                self.api.upload_file(path_or_fileobj=str(STATE_PATH),
                                     path_in_repo="send_state.json",
                                     repo_id="Valter3B/minerador_checkpoints",
                                     repo_type="dataset",
                                     token=self.hf_token)
            logger.info(f"{E['ok']} Campaign state saved (hash: {state_hash[:8]}...)")
        except Exception as e:
            logger.error(f"{E['error']} Failed to save campaign state: {e}")

    def load_campaign_state(self) -> Optional[CampaignState]:
        try:
            if not self.hf_token:
                logger.warning(f"{E['warn']} HF_TOKEN missing; cannot load campaign state from HF")
                return None
            file_path = self._download_file(repo_id="Valter3B/minerador_checkpoints", filename="send_state.json")
            with open(file_path, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
            state_data.setdefault("completed_domains", [])
            state_data.setdefault("pending_completion", {})
            return CampaignState(**state_data)
        except Exception as e:
            logger.warning(f"{E['warn']} No previous campaign state found: {e}")
            return None

# ===== IDEMPOTENCY MANAGER =====

class IdempotencyManager:
    def __init__(self, path: Path = IDEMPOTENCY_PATH):
        self.path = path
        self.lock = threading.Lock()
        self.sent_set: Set[str] = set()
        self._load()

    def _load(self):
        if not self.path.exists():
            self.sent_set = set()
            return
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.sent_set = set(data.get("sent_hashes", []))
            logger.info(f"{E['recover']} Idempotency loaded: {len(self.sent_set)} entries")
        except Exception as e:
            logger.warning(f"{E['warn']} Failed to load idempotency file: {e}")
            self.sent_set = set()

    def is_sent(self, email: str, account_id: str, day: int) -> bool:
        h = hashlib.sha256(f"{email}:{account_id}:{day}".encode()).hexdigest()
        return h in self.sent_set

    def mark_sent(self, email: str, account_id: str, day: int):
        h = hashlib.sha256(f"{email}:{account_id}:{day}".encode()).hexdigest()
        with self.lock:
            self.sent_set.add(h)

    def save(self):
        with self.lock:
            try:
                with open(self.path, 'w', encoding='utf-8') as f:
                    json.dump({"sent_hashes": list(self.sent_set)}, f, indent=2)
                logger.debug(f"{E['save']} Idempotency saved ({len(self.sent_set)})")
            except Exception as e:
                logger.error(f"{E['error']} Failed to save idempotency: {e}")

# ===== PROVISIONING MANAGER =====

class ProvisioningManager:
    def __init__(self):
        self.desec_tokens = config.desec_tokens
        self.desec_domain = config.desec_domain
        self.api_lock = threading.BoundedSemaphore(value=max(1, min(5, len(self.desec_tokens))))

    def allocate_ipv6_route64(self, token: str) -> Optional[str]:
        if not config.route64_key:
            logger.warning(f"{E['warn']} ROUTE64_API_KEY missing; cannot allocate IPv6")
            return None
        headers = {"Authorization": f"Bearer {token}"}
        try:
            with self.api_lock:
                resp = requests.post("https://api.route64.example/allocate", json={"type": "ipv6_single"}, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("ipv6_address")
                logger.warning(f"{E['warn']} Route64 allocation failed: {resp.status_code} {resp.text}")
                return None
        except Exception as e:
            logger.error(f"{E['error']} Route64 allocation error: {e}")
            return None

    def create_desec_records(self, subdomain: str, ipv6: str, dkim_selector: str, dkim_public_pem: str, token: str) -> bool:
        if not self.desec_domain:
            logger.warning(f"{E['warn']} DESEC_DOMAIN not configured")
            return False
        headers = {"Authorization": f"Token {token}", "Content-Type": "application/json"}
        try:
            with self.api_lock:
                payload = {
                    "rrsets": [
                        {
                            "name": f"{subdomain}.{self.desec_domain}.",
                            "type": "TXT",
                            "ttl": 3600,
                            "records": [f"v=spf1 ip6:{ipv6}/128 -all"]
                        },
                        {
                            "name": f"s2026._domainkey.{subdomain}.{self.desec_domain}.",
                            "type": "TXT",
                            "ttl": 3600,
                            "records": [dkim_public_pem.replace("\n", "\\n")]
                        }
                    ]
                }
                resp = requests.patch(f"https://desec.io/api/v1/domains/{self.desec_domain}/rrsets/", json=payload, headers=headers, timeout=10)
                if resp.status_code in (200, 201, 204):
                    logger.debug(f"{E['ok']} deSEC records created for {subdomain}.{self.desec_domain}")
                    return True
                logger.warning(f"{E['warn']} deSEC returned {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"{E['error']} deSEC record creation error: {e}")
            return False

    def create_account(self, account_id: int, dry_run: bool = False) -> Optional[VeriscopeAccount]:
        subdomain_name = f"sub{account_id:04d}"
        full_domain = f"{subdomain_name}.{self.desec_domain}"
        token = None
        if self.desec_tokens:
            token = self.desec_tokens[(account_id - 1) % len(self.desec_tokens)]
        try:
            private_key, public_key_pem = DKIMManager.generate_keypair()
            ipv6 = None
            if not dry_run and config.route64_key and token:
                ipv6 = self.allocate_ipv6_route64(config.route64_key)
            if not ipv6:
                if dry_run:
                    ipv6 = f"2001:db8::{account_id}"
                    logger.info(f"{E['test']} Dry-run IPv6 used for {full_domain}: {ipv6}")
                else:
                    logger.error(f"{E['error']} Cannot allocate IPv6 for {full_domain}; skipping account creation")
                    return None
            if not dry_run and token:
                created = self.create_desec_records(subdomain_name, ipv6, "s2026", public_key_pem, token)
                if not created:
                    logger.warning(f"{E['warn']} deSEC records not confirmed for {full_domain}")
            logger.info(f"{E['ok']} Account {account_id}: {full_domain} (ipv6={ipv6})")
            account = VeriscopeAccount(
                id=f"email_{account_id:04d}",
                address=f"alex@{full_domain}",
                ipv6=ipv6,
                dkim_selector="s2026",
                dkim_private_key=private_key,
                dkim_public_key=public_key_pem,
                status="active",
                daily_quota=50,
                daily_sent_today=0,
                total_sent=0,
                created_at=datetime.now(timezone.utc).isoformat()
            )
            return account
        except Exception as e:
            logger.error(f"{E['error']} Failed to create account {account_id}: {e}")
            return None

    def provision_all_accounts(self, num_accounts: int = 3000, dry_run: bool = False):
        logger.info(f"{E['start']} Provisioning {num_accounts} accounts...")
        if dry_run:
            logger.info(f"{E['test']} DRY RUN: No remote calls will be made (uses doc IPv6)")
        accounts: List[VeriscopeAccount] = []
        with ThreadPoolExecutor(max_workers=min(10, num_accounts)) as executor:
            futures = {executor.submit(self.create_account, i, dry_run): i for i in range(1, num_accounts + 1)}
            for future in as_completed(futures):
                i = futures[future]
                try:
                    acc = future.result()
                    if acc:
                        accounts.append(acc)
                    if len(accounts) % 100 == 0:
                        logger.info(f"{E['stats']} Progress: {len(accounts)}/{num_accounts}")
                except Exception as e:
                    logger.error(f"{E['error']} Account creation error for {i}: {e}")
        logger.info(f"{E['ok']} Provisioning complete: {len(accounts)}/{num_accounts} accounts created")
        hf = HFDataLoader()
        hf.save_sender_accounts(accounts)
        return accounts

# ===== SMTP SENDER =====

def _format_host_for_ipv6(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host

class SMTPSender:
    def __init__(self, account: VeriscopeAccount):
        self.account = account
        self.host = _format_host_for_ipv6(config.kumomta_host)
        self.port = config.kumomta_port

    async def send_email(self, to_email: str, subject: str, html_body: str, text_body: str) -> Tuple[bool, str]:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.account.address
            msg["To"] = to_email
            msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
            msg["Message-ID"] = f"<{secrets.token_hex(16)}@{self.account.address.split('@')[1]}>"
            part1 = MIMEText(text_body, "plain", "utf-8")
            part2 = MIMEText(html_body, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)
            raw_msg = msg.as_bytes()
            domain = self.account.address.split("@", 1)[1]
            try:
                sig = DKIMManager.sign_message(raw_msg, self.account.dkim_selector, domain, self.account.dkim_private_key)
                signed = sig + raw_msg
            except Exception:
                logger.warning(f"{E['warn']} DKIM signing failed; sending unsigned (may be rejected)")
                signed = raw_msg
            # Use async context manager
            try:
                async with aiosmtplib.SMTP(hostname=self.host, port=self.port, timeout=30) as smtp:
                    await smtp.sendmail(self.account.address, [to_email], signed)
                logger.debug(f"{E['ok']} Email sent to {to_email} from {self.account.address}")
                return True, "250"
            except Exception as e:
                logger.error(f"{E['error']} SMTP send error to {to_email}: {e}")
                return False, "550"
        except Exception as e:
            logger.error(f"{E['error']} Failed to prepare/send email to {to_email}: {e}")
            return False, "550"

# ===== BATCH PROCESSOR =====

class BatchProcessor:
    def __init__(self, dataset_source: str = "hf"):
        self.dataset_source = dataset_source
        self.hf_loader = HFDataLoader()
        self.is_test = (dataset_source == "env")
        self.is_production = (dataset_source == "hf")
        self.idempotency = IdempotencyManager()

    async def process_batch(self, batch: List[Dict], day: int, accounts: List[VeriscopeAccount], runner_id: int, total_runners: int) -> List[EmailResult]:
        results: List[EmailResult] = []
        leads_per_runner = max(1, len(batch) // total_runners)
        start_idx = (runner_id - 1) * leads_per_runner
        end_idx = start_idx + leads_per_runner if runner_id < total_runners else len(batch)
        runner_batch = batch[start_idx:end_idx]
        logger.info(f"{E['smtp']} Runner {runner_id}: Processing {len(runner_batch)} leads for Email {day}")
        template_gen = EmailTemplateGenerator(day, f"runner_{runner_id}")
        subject = template_gen.get_subject()
        for idx, lead in enumerate(runner_batch):
            email = lead.get("email")
            domain = lead.get("domain", "")
            if not email:
                continue
            try:
                validate_email(email)
            except EmailNotValidError:
                logger.debug(f"{E['warn']} Invalid email skipped: {email}")
                continue
            account = accounts[(start_idx + idx) % len(accounts)]
            if self.idempotency.is_sent(email, account.id, day):
                logger.debug(f"{E['info']} Skipping already-sent: {email} by {account.id}")
                continue
            html_body = template_gen.get_html_body(email, lead.get("name", ""))
            text_body = template_gen.get_text_body()
            sender = SMTPSender(account)
            success, smtp_code = await sender.send_email(to_email=email, subject=subject, html_body=html_body, text_body=text_body)
            result = EmailResult(
                lead_email=email,
                account_id=account.id,
                domain=domain,
                day=day,
                status="ACCEPTED" if success else "REJECTED",
                smtp_code=smtp_code,
                message="Email sent" if success else "SMTP error",
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            if success:
                self.idempotency.mark_sent(email, account.id, day)
            results.append(result)
            if (idx + 1) % 1000 == 0:
                logger.info(f"{E['stats']} Runner {runner_id}: {idx + 1}/{len(runner_batch)} processed")
        self.idempotency.save()
        logger.info(f"{E['ok']} Runner {runner_id}: Batch complete ({len(results)} emails)")
        return results

# ===== STATE MANAGER =====

class StateManager:
    def __init__(self):
        self.hf_loader = HFDataLoader()

    def create_initial_state(self, day: int = 1) -> CampaignState:
        return CampaignState(status="RUNNING", current_day=day, current_email_number=day, current_account_index=0,
                             current_domain="gmail.com", total_sent_today=0, total_sent_campaign=0,
                             last_checkpoint=datetime.now(timezone.utc).isoformat(), hash_sha256="", completed_domains=[],
                             pending_completion={}, session_number=1)

    def load_or_create_state(self, day: int) -> CampaignState:
        existing_state = self.hf_loader.load_campaign_state()
        if existing_state and existing_state.current_day == day:
            logger.info(f"{E['recover']} Recovered campaign state from HuggingFace")
            return existing_state
        logger.info(f"{E['ok']} Creating new campaign state for day {day}")
        return self.create_initial_state(day)

    def save_state(self, state: CampaignState):
        self.hf_loader.save_campaign_state(state)

# ===== ANALYTICS ENGINE =====

class AnalyticsEngine:
    def __init__(self):
        self.hf_loader = HFDataLoader()

    def generate_report(self, state: CampaignState, results: List[EmailResult]) -> Dict:
        accepted = sum(1 for r in results if r.status == "ACCEPTED")
        rejected = sum(1 for r in results if r.status == "REJECTED")
        throttled = sum(1 for r in results if r.status == "THROTTLED")
        acceptance_rate = (accepted / len(results) * 100) if results else 0
        by_domain = {}
        for result in results:
            d = result.domain
            by_domain.setdefault(d, {"accepted": 0, "rejected": 0, "throttled": 0})
            if result.status == "ACCEPTED":
                by_domain[d]["accepted"] += 1
            elif result.status == "REJECTED":
                by_domain[d]["rejected"] += 1
            else:
                by_domain[d]["throttled"] += 1
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "campaign_state": asdict(state),
            "summary": {"total_sent": len(results), "accepted": accepted, "rejected": rejected, "throttled": throttled, "acceptance_rate": f"{acceptance_rate:.1f}%"},
            "by_domain": by_domain
        }
        return report

    def save_report(self, report: Dict, filename: str = "campaign_report.json"):
        try:
            report_path = SAVE_PATH / filename
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            if config.hf_token:
                self.hf_loader.api.upload_file(path_or_fileobj=str(report_path),
                                               path_in_repo=f"reports/{filename}",
                                               repo_id="Valter3B/minerador_checkpoints",
                                               repo_type="dataset",
                                               token=config.hf_token)
            logger.info(f"{E['ok']} Report saved: {filename}")
        except Exception as e:
            logger.error(f"{E['error']} Failed to save report: {e}")

# ===== MAIN CAMPAIGN CLASS =====

class EmailCampaign:
    def __init__(self, dataset_source: str = "hf"):
        self.dataset_source = dataset_source
        self.is_test = (dataset_source == "env")
        self.is_production = (dataset_source == "hf")
        self.hf_loader = HFDataLoader()
        self.provisioner = ProvisioningManager()
        self.state_manager = StateManager()
        self.batch_processor = BatchProcessor(dataset_source=dataset_source)
        self.analytics = AnalyticsEngine()
        logger.info(f"{E['start']} Email Campaign initialized (source={dataset_source})")

    async def run(self, day: int = 1, runner_id: int = 1, total_runners: int = 20):
        logger.info(f"{E['start']} ===== CAMPAIGN START ===== Day={day} Runner={runner_id}/{total_runners}")
        state = self.state_manager.load_or_create_state(day)
        accounts = self.hf_loader.load_sender_accounts()
        if not accounts:
            logger.error(f"{E['error']} No accounts loaded. Please provision accounts first or provide HF_TOKEN.")
            return
        logger.info(f"{E['accounts']} Loaded {len(accounts)} accounts")
        all_results: List[EmailResult] = []
        leads_generator = self.batch_processor.hf_loader.load_leads_batch_generator(dataset_source=self.dataset_source)
        for batch_idx, batch in enumerate(leads_generator):
            logger.info(f"{E['list']} Processing batch {batch_idx + 1} ({len(batch)} leads)")
            results = await self.batch_processor.process_batch(batch, day, accounts, runner_id, total_runners)
            all_results.extend(results)
            state.total_sent_today += len(results)
            state.total_sent_campaign += len(results)
            state.last_checkpoint = datetime.now(timezone.utc).isoformat()
            if self.is_test or batch_idx % 10 == 0:
                self.state_manager.save_state(state)
        report = self.analytics.generate_report(state, all_results)
        self.analytics.save_report(report, f"report_day{day}_runner{runner_id}.json")
        if runner_id == total_runners:
            state.status = "COMPLETED"
            self.state_manager.save_state(state)
            logger.info(f"{E['ok']} ===== CAMPAIGN COMPLETE =====")
        logger.info(f"{E['stats']} Total sent this runner: {state.total_sent_today}")

# ===== CLI =====

async def main():
    parser = argparse.ArgumentParser(description="Veriscope Email Marketing Engine - corrected final")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")
    provision_parser = subparsers.add_parser("provision", help="Create sender accounts")
    provision_parser.add_argument("--num-accounts", type=int, default=3000)
    provision_parser.add_argument("--dry-run", action="store_true")
    send_parser = subparsers.add_parser("send", help="Send campaign emails")
    send_parser.add_argument("--dataset-source", choices=["env", "hf"], default="hf")
    send_parser.add_argument("--day", type=int, default=1)
    send_parser.add_argument("--runner-id", type=int, default=1)
    send_parser.add_argument("--total-runners", type=int, default=20)
    test_parser = subparsers.add_parser("test", help="Send test emails (4 leads)")
    test_parser.add_argument("--batch-size", type=int, default=4)
    report_parser = subparsers.add_parser("report", help="Generate campaign report")
    report_parser.add_argument("--day", type=int, default=1)
    args = parser.parse_args()
    if args.command == "provision":
        provisioner = ProvisioningManager()
        provisioner.provision_all_accounts(args.num_accounts, dry_run=args.dry_run)
    elif args.command == "send":
        campaign = EmailCampaign(dataset_source=args.dataset_source)
        await campaign.run(day=args.day, runner_id=args.runner_id, total_runners=args.total_runners)
    elif args.command == "test":
        campaign = EmailCampaign(dataset_source="env")
        await campaign.run(day=1, runner_id=1, total_runners=1)
    elif args.command == "report":
        analytics = AnalyticsEngine()
        logger.info(f"{E['stats']} Report generation (local/HF if configured)...")
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info(f"{E['warn']} Interrupted by user")
