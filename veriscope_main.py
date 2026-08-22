#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Veriscope Email Campaign Engine
Complete system for sending 30M emails in 5 days with mutations and state management.
"""

import os
import sys
import json
import asyncio
import logging
import hashlib
import random
import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
import pandas as pd
from huggingface_hub import hf_hub_download, HfApi
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import dkimpy
from email_validator import validate_email, EmailNotValidError
from tenacity import retry, stop_after_attempt, wait_exponential
import base64

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('veriscope.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Global configuration."""
    
    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN")
        self.hf_repo = os.getenv("HF_REPO", "Valter3B/Trader_Emails")
        
        self.kumomta_host = os.getenv("KUMOMTA_HOST", "2a11:6c7:f10:5::1")
        self.kumomta_port = int(os.getenv("KUMOMTA_PORT", "2525"))
        
        self.desec_domain = os.getenv("DESEC_DOMAIN", "oeudominio.dedyn.io")
        self.from_name = os.getenv("KUMOMTA_FROM_NAME", "Alex | Liquidity Alert")
        
        # Test emails
        self.test_emails = [
            os.getenv("TEST_EMAIL_GMAIL", ""),
            os.getenv("TEST_EMAIL_OUTLOOK", ""),
            os.getenv("TEST_EMAIL_PROTONMAIL", ""),
            os.getenv("TEST_EMAIL_HOTMAIL", "")
        ]
        self.test_emails = [e for e in self.test_emails if e]  # Remove empty
        
        # Desec tokens (26)
        self.desec_tokens = [
            os.getenv(f"DESEC_TOKEN_{i}") for i in range(1, 27)
        ]
        self.desec_tokens = [t for t in self.desec_tokens if t]  # Remove empty
        
        logger.info(f"Config loaded: {len(self.desec_tokens)} deSEC tokens, {len(self.test_emails)} test emails")

config = Config()

# ============================================================================
# EMAIL TEMPLATES (COMPLETE, PORTUGUESE)
# ============================================================================

class EmailTemplates:
    """Complete email templates for 5-day campaign (Portuguese)."""
    
    LOGO_SVG = """
    <svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
        <rect width="100" height="100" rx="10" fill="#2563eb"/>
        <circle cx="50" cy="30" r="15" fill="white"/>
        <polygon points="50,50 30,70 70,70" fill="white"/>
        <text x="50" y="85" text-anchor="middle" fill="white" font-size="10" font-weight="bold">V</text>
    </svg>
    """
    
    CSS_BASE = """
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        line-height: 1.6;
        color: #333;
        background-color: #f9f9f9;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 600px;
        margin: 0 auto;
        background-color: #ffffff;
        padding: 40px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .header {
        text-align: center;
        margin-bottom: 30px;
    }
    .logo {
        width: 100px;
        height: auto;
        margin-bottom: 20px;
    }
    .content {
        margin: 20px 0;
        font-size: 16px;
        line-height: 1.8;
    }
    .button {
        display: inline-block;
        background-color: #2563eb;
        color: #ffffff;
        padding: 14px 32px;
        text-decoration: none;
        border-radius: 6px;
        font-weight: bold;
        text-align: center;
        margin: 20px 0;
        border: none;
        cursor: pointer;
        font-size: 16px;
    }
    .button:hover {
        background-color: #1d4ed8;
    }
    .footer {
        text-align: center;
        font-size: 12px;
        color: #999;
        margin-top: 40px;
        border-top: 1px solid #eee;
        padding-top: 20px;
    }
    .hidden {
        display: none;
    }
    """
    
    @staticmethod
    def get_email_1() -> Dict:
        """Email 1: Posso mostrar-te algo amanhã?"""
        return {
            "day": 1,
            "subject": "[1/5] Posso mostrar-te algo amanhã?",
            "button_text": "Ver a ideia",
            "button_url": "https://veriscope-com-session-matrix.pages.dev/",
            "html": """
            <!DOCTYPE html>
            <html lang="pt">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Posso mostrar-te algo amanhã?</title>
                <style>""" + EmailTemplates.CSS_BASE + """</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        """ + EmailTemplates.LOGO_SVG + """
                        <h2>Veriscope</h2>
                    </div>
                    
                    <div class="content">
                        <p>Olá,</p>
                        
                        <p>Se já estás há alguns anos no trading, provavelmente já viste isto acontecer:</p>
                        
                        <p>Um trader perde uma operação e a primeira pergunta que faz é:</p>
                        
                        <p><strong>"O que está a faltar no meu gráfico?"</strong></p>
                        
                        <p>Depois adiciona mais uma confirmação. Mais um indicador. Mais uma linha. Mais uma coisa para observar.</p>
                        
                        <p>E, durante algum tempo, parece fazer sentido.</p>
                        
                        <p>Mas existe uma pergunta que quase ninguém faz:</p>
                        
                        <p><strong>E se o problema não for falta de informação?</strong></p>
                        
                        <p>Nós começámos a pensar nisso há algum tempo.</p>
                        
                        <p>Porque um trader experiente já sabe que não precisa de olhar para um gráfico durante 24 horas. Também sabe que nem todas as horas têm a mesma importância.</p>
                        
                        <p>Mesmo assim, muitos continuam a gastar tempo a observar o mercado… à espera de algo que talvez nem estivesse perto de acontecer.</p>
                        
                        <p>Não estou a dizer que precisas de mudar a tua estratégia. Nem aprender um método novo.</p>
                        
                        <p>Na verdade, amanhã vou mostrar-te uma ferramenta que nasceu precisamente de uma pergunta que talvez tu próprio já tenhas feito.</p>
                        
                        <p><strong>E se soubéssemos melhor quando vale realmente a pena prestar atenção?</strong></p>
                        
                        <p>Chama-se <strong>Veriscope Session Matrix</strong>.</p>
                        
                        <p>Ainda não te vou explicar exatamente o que ela faz. Prefiro que primeiro vejas a ideia que levou à sua criação.</p>
                        
                        <p style="text-align: center;">
                            <a href="https://veriscope-com-session-matrix.pages.dev/" class="button">Ver a ideia</a>
                        </p>
                        
                        <p>Amanhã, à mesma hora, envio-te o próximo e-mail.</p>
                        
                        <p>E, desta vez, vais perceber porque decidimos criar esta ferramenta.</p>
                        
                        <p>Depois, vais poder ter acesso a ela. Sem custos. Sem cartão. Sem conta.</p>
                        
                        <p>Até amanhã.</p>
                        
                        <p>Alex<br><strong>Liquidity Alert</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2026 Veriscope. Todos os direitos reservados.<br>
                        Recebeste este email porque te interessa trading.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
    
    @staticmethod
    def get_email_2() -> Dict:
        """Email 2: A pergunta que levou ao Session Matrix"""
        return {
            "day": 2,
            "subject": "[2/5] A pergunta que levou ao Session Matrix",
            "button_text": "Ver o Session Matrix",
            "button_url": "https://veriscope-com-session-matrix.pages.dev/",
            "html": """
            <!DOCTYPE html>
            <html lang="pt">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>A pergunta que levou ao Session Matrix</title>
                <style>""" + EmailTemplates.CSS_BASE + """</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        """ + EmailTemplates.LOGO_SVG + """
                        <h2>Veriscope</h2>
                    </div>
                    
                    <div class="content">
                        <p>Olá,</p>
                        
                        <p>Ontem falei-te de uma pergunta:</p>
                        
                        <p><strong>E se o problema não for falta de informação?</strong></p>
                        
                        <p>A pergunta parece simples. Mas levou-nos a olhar para o trading de outra forma.</p>
                        
                        <p>Porque existe uma coisa que muitos traders fazem sem perceber. Passam horas à frente do gráfico. Esperam. Analisam. Voltam mais tarde.</p>
                        
                        <p>E, quando finalmente o mercado faz algo importante, muitas vezes o movimento já passou.</p>
                        
                        <p>Não porque não sabiam analisar. Mas porque estavam a tentar dar atenção a tudo.</p>
                        
                        <p>E ninguém consegue dar atenção máxima a tudo.</p>
                        
                        <p>Foi daí que nasceu o <strong>Veriscope Session Matrix</strong>.</p>
                        
                        <p>Ele não te diz quando comprar. Não te diz quando vender. Não tenta substituir a tua análise.</p>
                        
                        <p>E não pede que mudes a forma como já operas.</p>
                        
                        <p>A pergunta que ele tenta ajudar a responder é mais simples:</p>
                        
                        <p><strong>Quando é que vale a pena olhar com mais atenção?</strong></p>
                        
                        <p>Mas há uma segunda parte desta história.</p>
                        
                        <p>Porque, quando sabes quando prestar atenção, uma nova pergunta aparece quase imediatamente:</p>
                        
                        <p><strong>"Certo. Agora que estou aqui… o que é que realmente importa no gráfico?"</strong></p>
                        
                        <p>Foi essa segunda pergunta que nos levou a construir algo maior. O <strong>Veriscope Prime</strong>.</p>
                        
                        <p>Não vou tentar explicar tudo neste e-mail. Mas na página abaixo vais encontrar o Session Matrix e, antes dele, vais poder conhecer aquilo que estamos a preparar com o Prime.</p>
                        
                        <p style="text-align: center;">
                            <a href="https://veriscope-com-session-matrix.pages.dev/" class="button">Ver o Session Matrix</a>
                        </p>
                        
                        <p>O Session Matrix está lá. É teu. Pine Script v6. Sem subscrição. Sem cartão. Sem conta.</p>
                        
                        <p>E uma coisa importante: não precisas de concordar connosco. Experimenta. Olha para o teu gráfico. E decide por ti se a ideia faz sentido.</p>
                        
                        <p>Amanhã vou falar-te da segunda pergunta. Aquela que aparece depois de saberes quando olhar.</p>
                        
                        <p>Até amanhã.</p>
                        
                        <p>Alex<br><strong>Liquidity Alert</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2026 Veriscope. Todos os direitos reservados.<br>
                        Recebeste este email porque te interessa trading.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
    
    @staticmethod
    def get_email_3() -> Dict:
        """Email 3: Saber quando olhar resolveu só metade"""
        return {
            "day": 3,
            "subject": "[3/5] Saber quando olhar resolveu só metade",
            "button_text": "Ver o Veriscope Prime",
            "button_url": "https://veriscope-com-session-matrix-access.pages.dev/",
            "html": """
            <!DOCTYPE html>
            <html lang="pt">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Saber quando olhar resolveu só metade</title>
                <style>""" + EmailTemplates.CSS_BASE + """</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        """ + EmailTemplates.LOGO_SVG + """
                        <h2>Veriscope</h2>
                    </div>
                    
                    <div class="content">
                        <p>Olá,</p>
                        
                        <p>Ontem entreguei-te o Veriscope Session Matrix.</p>
                        
                        <p>Mas existe uma coisa curiosa.</p>
                        
                        <p>Quando sabes que determinado momento merece mais atenção, o trabalho não termina.</p>
                        
                        <p>Na verdade, outra pergunta fica ainda mais clara:</p>
                        
                        <p><strong>"O que é que estou realmente a olhar?"</strong></p>
                        
                        <p>Imagina que finalmente chegas ao gráfico no momento certo. Agora tens estrutura. Liquidez. Zonas. Movimentos maiores e menores. Vários períodos para comparar.</p>
                        
                        <p>O problema não é que não sabes o que essas coisas são. Se já tens experiência, provavelmente sabes.</p>
                        
                        <p>O problema é outro: quanto trabalho precisas de fazer para juntar tudo outra vez?</p>
                        
                        <p>Desenhar. Comparar. Mudar de período. Voltar atrás. Tentar lembrar porque determinada zona ainda importa.</p>
                        
                        <p>Foi aí que tivemos uma espécie de "clique".</p>
                        
                        <p>Talvez o trader não precise de mais uma coisa para aprender. Talvez precise de uma forma melhor de ver juntas as coisas que já sabe ler.</p>
                        
                        <p>Foi assim que nasceu o <strong>Veriscope Prime</strong>.</p>
                        
                        <p>O Prime não foi criado para decidir por ti. Não é uma máquina de sinais. E não promete saber o que o mercado vai fazer.</p>
                        
                        <p>Ele foi criado para ajudar a organizar no gráfico o contexto que já existe à tua frente.</p>
                        
                        <p>Estrutura. Liquidez. Zonas. E contexto de vários períodos.</p>
                        
                        <p>A ideia não é dar-te mais coisas para olhar. É ajudar-te a reconstruir menos.</p>
                        
                        <p style="text-align: center;">
                            <a href="https://veriscope-com-session-matrix-access.pages.dev/" class="button">Ver o Veriscope Prime</a>
                        </p>
                        
                        <p>Amanhã vou falar-te de uma coisa que descobrimos depois.</p>
                        
                        <p>Porque ver melhor o gráfico é importante. Mas existe outra parte do trading que continua a existir antes, durante e depois da análise.</p>
                        
                        <p>E é exatamente aí que entra a segunda ferramenta do Veriscope.</p>
                        
                        <p>Até amanhã.</p>
                        
                        <p>Alex<br><strong>Liquidity Alert</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2026 Veriscope. Todos os direitos reservados.<br>
                        Recebeste este email porque te interessa trading.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
    
    @staticmethod
    def get_email_4() -> Dict:
        """Email 4: O gráfico é só uma parte"""
        return {
            "day": 4,
            "subject": "[4/5] O gráfico é só uma parte",
            "button_text": "Conhecer o Veriscope Edge",
            "button_url": "https://veriscope-com-session-matrix-access.pages.dev/",
            "html": """
            <!DOCTYPE html>
            <html lang="pt">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>O gráfico é só uma parte</title>
                <style>""" + EmailTemplates.CSS_BASE + """</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        """ + EmailTemplates.LOGO_SVG + """
                        <h2>Veriscope</h2>
                    </div>
                    
                    <div class="content">
                        <p>Olá,</p>
                        
                        <p>Durante estes dias falámos sobre duas perguntas.</p>
                        
                        <p><strong>Quando vale a pena prestar atenção?</strong></p>
                        
                        <p>E:</p>
                        
                        <p><strong>O que é que realmente importa quando estás a olhar?</strong></p>
                        
                        <p>O Session Matrix nasceu da primeira. O Prime nasceu da segunda.</p>
                        
                        <p>Mas existe uma terceira parte que não aparece no gráfico.</p>
                        
                        <p>Pensa no que acontece à volta de uma operação.</p>
                        
                        <p>Antes de entrar, precisas de pensar no risco. No tamanho da posição. No que estás disposto a perder.</p>
                        
                        <p>Depois, tens operações para rever. Erros para encontrar. Dias bons. Dias maus. Drawdown. Planeamento. Registos.</p>
                        
                        <p>Muitos traders fazem tudo isto. Mas fazem em sítios diferentes.</p>
                        
                        <p>Uma calculadora aqui. Um Excel ali. Um documento guardado algures. Um diário que começou e depois foi abandonado.</p>
                        
                        <p>E foi por isso que criámos o <strong>Veriscope Edge</strong>.</p>
                        
                        <p>De forma simples: é um espaço de trabalho em Excel com 19 ferramentas para ajudar a organizar o processo de trading.</p>
                        
                        <p>Inclui ferramentas para: gerir risco, calcular o tamanho da posição, acompanhar o desempenho, registar operações, acompanhar drawdown, planear melhor.</p>
                        
                        <p>O Edge não lê o mercado por ti. E também não é mais um indicador. Ele trabalha fora do gráfico.</p>
                        
                        <p>O Prime ajuda-te a organizar o contexto que vês. O Edge ajuda-te a organizar parte do processo à volta das tuas decisões.</p>
                        
                        <p style="text-align: center;">
                            <a href="https://veriscope-com-session-matrix-access.pages.dev/" class="button">Conhecer o Veriscope Edge</a>
                        </p>
                        
                        <p>Amanhã é o último e-mail desta sequência.</p>
                        
                        <p>E vou finalmente mostrar-te como estas duas ferramentas foram pensadas para se encaixar.</p>
                        
                        <p>Sem dizer que precisas das duas. Sem tentar decidir por ti. Apenas para que possas ver o quadro completo e escolher por onde faz sentido começar.</p>
                        
                        <p>Até amanhã.</p>
                        
                        <p>Alex<br><strong>Liquidity Alert</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2026 Veriscope. Todos os direitos reservados.<br>
                        Recebeste este email porque te interessa trading.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
    
    @staticmethod
    def get_email_5() -> Dict:
        """Email 5: Agora já conheces o quadro completo"""
        return {
            "day": 5,
            "subject": "[5/5] Agora já conheces o quadro completo",
            "button_text": "Conhecer o Veriscope",
            "button_url": "https://veriscope-com-prime.pages.dev/",
            "html": """
            <!DOCTYPE html>
            <html lang="pt">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Agora já conheces o quadro completo</title>
                <style>""" + EmailTemplates.CSS_BASE + """</style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        """ + EmailTemplates.LOGO_SVG + """
                        <h2>Veriscope</h2>
                    </div>
                    
                    <div class="content">
                        <p>Olá,</p>
                        
                        <p>Há cinco dias, comecei com uma pergunta:</p>
                        
                        <p><strong>E se o problema não for falta de informação?</strong></p>
                        
                        <p>Depois falámos sobre outra:</p>
                        
                        <p><strong>Quando é que vale a pena prestar atenção?</strong></p>
                        
                        <p>Foi por isso que te entregámos o Veriscope Session Matrix.</p>
                        
                        <p>Depois veio a próxima pergunta:</p>
                        
                        <p><strong>Quando chego ao gráfico no momento certo, o que é que realmente importa?</strong></p>
                        
                        <p>Foi aí que conheceste o Veriscope Prime.</p>
                        
                        <p>E ontem falámos de uma parte que existe fora do gráfico:</p>
                        
                        <p>Risco. Tamanho da posição. Registo. Desempenho. Planeamento.</p>
                        
                        <p>Foi aí que te apresentei o Veriscope Edge.</p>
                        
                        <p>Agora talvez consigas ver a forma como pensamos no Veriscope.</p>
                        
                        <p>Não criámos duas versões da mesma coisa. Cada ferramenta resolve uma parte diferente:</p>
                        
                        <p><strong>Session Matrix</strong> → Quando prestar atenção.</p>
                        
                        <p><strong>Prime</strong> → O que estás a olhar.</p>
                        
                        <p><strong>Edge</strong> → Como organizas o processo à volta disso.</p>
                        
                        <p>Durante esta semana, não te pedi para comprar nada.</p>
                        
                        <p>Primeiro mostrámos uma ideia. Depois entregámos aquilo que prometemos. Depois deixámos-te conhecer o que estava por trás dessa ideia.</p>
                        
                        <p>E agora chegámos ao último passo.</p>
                        
                        <p>O Veriscope está oficialmente em lançamento.</p>
                        
                        <p>Se, depois destes cinco dias, alguma parte do que viste fez sentido para a forma como trabalhas, podes conhecer o ecossistema completo aqui:</p>
                        
                        <p style="text-align: center;">
                            <a href="https://veriscope-com-prime.pages.dev/" class="button">Conhecer o Veriscope</a>
                        </p>
                        
                        <p>Não precisas de mudar a tua estratégia. Não precisas de concordar connosco. E certamente não precisas de comprar alguma coisa só porque chegaste ao último e-mail.</p>
                        
                        <p>A decisão continua a ser tua.</p>
                        
                        <p>Nós apenas queríamos mostrar-te uma forma diferente de olhar para o processo.</p>
                        
                        <p>Porque talvez não precises de mais informação. Talvez precises apenas de usar melhor a informação que já tens.</p>
                        
                        <p>Obrigado por acompanhares estes cinco dias.</p>
                        
                        <p>Alex<br><strong>Liquidity Alert</strong></p>
                    </div>
                    
                    <div class="footer">
                        <p>&copy; 2026 Veriscope. Todos os direitos reservados.<br>
                        Recebeste este email porque te interessa trading.</p>
                    </div>
                </div>
            </body>
            </html>
            """
        }
    
    @staticmethod
    def get_email(day: int) -> Dict:
        """Get email template for a specific day (1-5)."""
        emails = {
            1: EmailTemplates.get_email_1(),
            2: EmailTemplates.get_email_2(),
            3: EmailTemplates.get_email_3(),
            4: EmailTemplates.get_email_4(),
            5: EmailTemplates.get_email_5()
        }
        if day not in emails:
            raise ValueError(f"Invalid day: {day}. Must be 1-5.")
        return emails[day]

# ============================================================================
# MUTATION ENGINE (Fuzzy Hash Evasion)
# ============================================================================

class MutationEngine:
    """Applies mutations to emails without changing visible content."""
    
    def __init__(self, account_id: str, day: int):
        self.account_id = account_id
        self.day = day
        self.seed = hash(f"{account_id}_{day}") % 10000
        random.seed(self.seed)
    
    def apply_mutations(self, html: str, lead_email: str) -> str:
        """
        Apply mutations to HTML:
        - Hidden comments
        - Invisible Unicode spaces
        - Random CSS classes
        - Unique tracking params
        """
        
        # Generate random hidden elements
        random_class_1 = f"rnd_{random.randint(10000, 99999)}"
        random_class_2 = f"rnd_{random.randint(10000, 99999)}"
        hidden_text_1 = f"hidden_{random.randint(1000, 9999)}"
        hidden_text_2 = f"hidden_{random.randint(1000, 9999)}"
        
        # Generate tracking hash
        tracking_hash = hashlib.sha256(
            f"{self.account_id}_{lead_email}_{self.day}_{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Inject mutations before the footer
        mutation_html = f"""
        <!-- Hidden mutation marker: {hidden_text_1} -->
        <div style="display:none;" class="{random_class_1}"><!-- Invisible element --></div>
        <span style="color:inherit; font-size:0;" class="{random_class_2}" data-tracking="{hidden_text_2}"></span>
        """
        
        # Insert mutation marker before closing body tag
        mutated = html.replace("</body>", mutation_html + "\n</body>")
        
        # Add tracking pixel (before closing body)
        tracking_pixel = f"""
        <img src="https://tracking.veriscope.com/pixel?lead={lead_email}&day={self.day}&hash={tracking_hash}" alt="" width="1" height="1" style="display:none;">
        """
        
        mutated = mutated.replace("</body>", tracking_pixel + "\n</body>")
        
        return mutated

# ============================================================================
# DKIM SIGNER
# ============================================================================

class DKIMSigner:
    """Signs emails with DKIM."""
    
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate RSA 2048 key pair for DKIM."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_b64 = base64.b64encode(public_der).decode('utf-8')
        
        return private_pem, public_b64
    
    @staticmethod
    def sign_message(message: bytes, private_key_pem: str, domain: str, selector: str = "s2026") -> bytes:
        """Sign message with DKIM using dkimpy."""
        try:
            return dkimpy.sign(
                message,
                selector.encode(),
                domain.encode(),
                private_key_pem.encode(),
                canonicalize=(b'relaxed', b'relaxed'),
                include_headers=(b'From', b'To', b'Subject', b'Date', b'Message-ID'),
            )
        except Exception as e:
            logger.error(f"DKIM signing error: {e}")
            return message  # Return unsigned on error

# ============================================================================
# SMTP SENDER
# ============================================================================

class SMTPSender:
    """Handles SMTP communication."""
    
    def __init__(self, account_email: str):
        self.account_email = account_email
        self.host = config.kumomta_host
        self.port = config.kumomta_port
        self.timeout = 30
    
    async def send_email(self, to_email: str, subject: str, html_body: str, dkim_private_key: str = None) -> Tuple[bool, str]:
        """
        Send email via SMTP.
        Returns: (success: bool, response_code: str)
        """
        
        try:
            # Validate recipient email
            try:
                validate_email(to_email)
            except EmailNotValidError as e:
                logger.warning(f"Invalid email: {to_email} - {e}")
                return False, "400 Invalid email"
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{config.from_name} <{self.account_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Reply-To'] = self.account_email
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            msg['Message-ID'] = f"<{hashlib.sha256((to_email + datetime.utcnow().isoformat()).encode()).hexdigest()}@{config.desec_domain}>"
            
            # Add HTML part
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)
            
            # Convert to bytes
            message_bytes = msg.as_bytes()
            
            # Sign with DKIM if key provided
            if dkim_private_key:
                message_bytes = DKIMSigner.sign_message(
                    message_bytes,
                    dkim_private_key,
                    config.desec_domain
                )
            
            # Connect and send via IPv6
            formatted_host = f"[{self.host}]" if ':' in self.host else self.host
            
            async with aiosmtplib.SMTP(
                hostname=formatted_host,
                port=self.port,
                timeout=self.timeout,
                use_tls=False  # WireGuard is already private
            ) as smtp:
                await smtp.ehlo()
                await smtp.sendmail(self.account_email, [to_email], message_bytes)
            
            logger.info(f"✓ Email sent to {to_email} from {self.account_email}")
            return True, "250 OK"
        
        except aiosmtplib.SMTPException as e:
            error_str = str(e)
            logger.warning(f"SMTP error for {to_email}: {error_str}")
            
            if error_str.startswith("4"):
                return False, f"4xx Throttle"
            elif error_str.startswith("5"):
                return False, f"5xx Reject"
            else:
                return False, f"SMTP Error"
        
        except Exception as e:
            logger.error(f"Unexpected error sending to {to_email}: {e}")
            return False, f"Exception: {type(e).__name__}"

# ============================================================================
# STATE MANAGER
# ============================================================================

class StateManager:
    """Manages campaign state and checkpoints."""
    
    def __init__(self, day: int, runner_id: int):
        self.day = day
        self.runner_id = runner_id
        self.state = {
            "day": day,
            "runner_id": runner_id,
            "status": "running",
            "total_sent": 0,
            "total_processed": 0,
            "checkpoint_count": 0,
            "started_at": datetime.utcnow().isoformat(),
            "last_checkpoint": None,
            "emails_sent": []
        }
        self.state_file = f"campaign_state_day{day}_runner{runner_id}.json"
        self.load_state()
    
    def load_state(self):
        """Load state from file (recovery)."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    saved = json.load(f)
                    self.state.update(saved)
                    logger.info(f"Recovered state: {self.state['total_sent']} emails sent")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
    
    def save_state(self):
        """Checkpoint state."""
        self.state['last_checkpoint'] = datetime.utcnow().isoformat()
        self.state['checkpoint_count'] = self.state.get('checkpoint_count', 0) + 1
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            
            # Calculate SHA-256 for validation
            sha256 = hashlib.sha256(json.dumps(self.state).encode()).hexdigest()
            logger.info(f"State saved (checkpoint #{self.state['checkpoint_count']}, SHA-256: {sha256[:8]}...)")
        
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def add_sent(self, email_info: Dict):
        """Record a sent email."""
        self.state['total_sent'] += 1
        self.state['total_processed'] += 1
        self.state['emails_sent'].append(email_info)

# ============================================================================
# BATCH PROCESSOR
# ============================================================================

class BatchProcessor:
    """Processes and sends batches of emails."""
    
    def __init__(self, day: int, runner_id: int, total_runners: int, dataset_source: str = 'hf'):
        self.day = day
        self.runner_id = runner_id
        self.total_runners = total_runners
        self.dataset_source = dataset_source
        self.state_manager = StateManager(day, runner_id)
        self.email_template = EmailTemplates.get_email(day)
    
    async def process_batch(self, leads: List[Dict], accounts: List[Dict]) -> Dict:
        """
        Send batch of emails.
        Returns stats dict.
        """
        
        stats = {
            "sent": 0,
            "throttled": 0,
            "rejected": 0,
            "failed": 0
        }
        
        for idx, lead in enumerate(leads):
            # Round-robin account selection
            account_idx = (self.runner_id + idx) % len(accounts)
            account = accounts[account_idx]
            
            # Apply mutations
            mutator = MutationEngine(account['id'], self.day)
            html_body = mutator.apply_mutations(self.email_template['html'], lead['email'])
            
            # Send email
            sender = SMTPSender(account['email'])
            success, response = await sender.send_email(
                to_email=lead['email'],
                subject=self.email_template['subject'],
                html_body=html_body,
                dkim_private_key=account.get('dkim_private_key')
            )
            
            # Record result
            if success:
                stats["sent"] += 1
                email_info = {
                    "email": lead['email'],
                    "account": account['id'],
                    "status": "ACCEPTED",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                if "4xx" in response:
                    stats["throttled"] += 1
                    status = "THROTTLED"
                elif "5xx" in response:
                    stats["rejected"] += 1
                    status = "REJECTED"
                else:
                    stats["failed"] += 1
                    status = "FAILED"
                
                email_info = {
                    "email": lead['email'],
                    "account": account['id'],
                    "status": status,
                    "response": response,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            self.state_manager.add_sent(email_info)
            
            # Progress logging (every 1000 emails)
            if (idx + 1) % 1000 == 0:
                logger.info(f"Progress: {idx + 1}/{len(leads)} emails processed")
            
            # Checkpoint every 5000 emails
            if (idx + 1) % 5000 == 0:
                self.state_manager.save_state()
        
        # Final checkpoint
        self.state_manager.save_state()
        
        return stats

# ============================================================================
# HUGGINGFACE DATA LOADER
# ============================================================================

class HFDataLoader:
    """Loads data from HuggingFace."""
    
    def __init__(self):
        self.token = config.hf_token
        self.repo = config.hf_repo
    
    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def load_sender_accounts(self) -> List[Dict]:
        """Load sender accounts from HF."""
        try:
            file_path = hf_hub_download(
                repo_id=self.repo,
                filename="sender_accounts.json",
                token=self.token
            )
            
            with open(file_path, 'r') as f:
                accounts = json.load(f)
            
            logger.info(f"✓ Loaded {len(accounts)} accounts from HF")
            return accounts
        
        except Exception as e:
            logger.error(f"Failed to load accounts: {e}")
            raise
    
    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=2, max=10))
    def load_leads_batch(self, batch_num: int = 1, batch_size: int = 100000) -> List[Dict]:
        """Load leads batch from HF."""
        try:
            file_path = hf_hub_download(
                repo_id=self.repo,
                filename=f"leads_batch_{batch_num}.parquet",
                token=self.token
            )
            
            df = pd.read_parquet(file_path)
            leads = df.to_dict('records')
            
            logger.info(f"✓ Loaded {len(leads)} leads from batch {batch_num}")
            return leads
        
        except Exception as e:
            logger.error(f"Failed to load leads batch {batch_num}: {e}")
            raise

# ============================================================================
# MAIN CAMPAIGN ORCHESTRATOR
# ============================================================================

async def run_campaign(day: int, runner_id: int, total_runners: int, dataset_source: str = 'hf'):
    """Main campaign runner."""
    
    logger.info("=" * 80)
    logger.info(f"VERISCOPE EMAIL CAMPAIGN")
    logger.info(f"Day: {day}, Runner: {runner_id}/{total_runners}, Source: {dataset_source.upper()}")
    logger.info("=" * 80)
    
    # Load accounts
    hf_loader = HFDataLoader()
    accounts = hf_loader.load_sender_accounts()
    logger.info(f"✓ Loaded {len(accounts)} sender accounts")
    
    # Load leads based on source
    if dataset_source == 'env':
        # Test mode: use 4 test emails
        leads = [
            {"email": e, "domain": e.split('@')[1]}
            for e in config.test_emails
        ]
        logger.info(f"✓ TEST MODE: Loaded {len(leads)} test emails")
    else:
        # Production: load from HF
        leads = hf_loader.load_leads_batch(batch_num=1)
        logger.info(f"✓ PRODUCTION MODE: Loaded {len(leads)} leads")
    
    # Create batch processor
    processor = BatchProcessor(day, runner_id, total_runners, dataset_source)
    
    # Process emails in batches
    batch_size = 1000
    total_batches = (len(leads) + batch_size - 1) // batch_size
    
    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min(start_idx + batch_size, len(leads))
        batch = leads[start_idx:end_idx]
        
        logger.info(f"Processing batch {batch_num + 1}/{total_batches} ({len(batch)} emails)...")
        
        stats = await processor.process_batch(batch, accounts)
        
        logger.info(f"Batch {batch_num + 1}: {stats['sent']} sent, "
                   f"{stats['throttled']} throttled, {stats['rejected']} rejected, {stats['failed']} failed")
    
    logger.info(f"✓ Campaign complete: {processor.state_manager.state['total_sent']} emails sent")
    logger.info("=" * 80)

# ============================================================================
# CLI
# ============================================================================

def main():
    """CLI entry point."""
    
    parser = argparse.ArgumentParser(
        description="Veriscope Email Campaign Engine"
    )
    
    parser.add_argument(
        '--dataset-source',
        type=str,
        choices=['env', 'hf'],
        default='hf',
        help="Data source: 'env' (4 test emails) or 'hf' (HuggingFace dataset)"
    )
    
    parser.add_argument(
        '--day',
        type=int,
        default=1,
        help="Campaign day (1-5)"
    )
    
    parser.add_argument(
        '--runner-id',
        type=int,
        default=1,
        help="Runner ID"
    )
    
    parser.add_argument(
        '--total-runners',
        type=int,
        default=20,
        help="Total runners"
    )
    
    args = parser.parse_args()
    
    # Validate day
    if not (1 <= args.day <= 5):
        logger.error("Day must be between 1 and 5")
        sys.exit(1)
    
    # Validate runner
    if not (1 <= args.runner_id <= args.total_runners):
        logger.error(f"Runner ID must be between 1 and {args.total_runners}")
        sys.exit(1)
    
    # Run async campaign
    try:
        asyncio.run(run_campaign(
            args.day,
            args.runner_id,
            args.total_runners,
            args.dataset_source
        ))
    except KeyboardInterrupt:
        logger.info("Campaign interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Campaign failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
