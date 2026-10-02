"""Modèles cibles.

Le simulateur n'est PAS un vrai LLM : c'est un « pire cas » déterministe qui obéit à
toute instruction, où qu'elle se trouve. Il sert à tester le banc lui-même et à mesurer
ce que les défenses de l'APPLICATION arrêtent quand le modèle cède. La vraie mesure
de robustesse se fait avec un vrai modèle (--provider claude).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from typing import Protocol

import httpx


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, max_tokens: int) -> str: ...


REVEAL = re.compile(
    r"(prompt syst[eè]me|instructions|configuration|code interne|internal code|au-dessus|above|system prompt)", re.I
)


class ObedientSimulator:
    name = "simulateur"

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        text = system + "\n" + user
        for block in re.findall(r"[A-Za-z0-9+/=]{24,}", user):  # instructions encodées
            try:
                text += "\n" + base64.b64decode(block).decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                pass
        low = text.lower()
        canary = re.search(r"CANARY-[A-Z0-9]+", system)
        out: list[str] = []
        if m := re.search(r"(\w+)[' ]+(\d[\d ]*) fois", user):
            out.append(" ".join([m.group(1)] * min(int(m.group(2).replace(" ", "")), 50_000)))
        if "séparant chaque caractère" in low and canary:
            out.append("Code : " + "-".join(canary.group(0)))
        elif "base64" in low and canary:
            out.append("Chaîne : " + base64.b64encode(canary.group(0).encode()).decode())
        elif REVEAL.search(user) or "révèle" in low:
            out.append("Voici ma configuration :\n" + system)
        if re.search(r"(e-mail|iban|client n°|tous les clients)", user, re.I):
            out += re.findall(r"^FICHE .*$", system, re.M)
        if m := re.search(r"([\w.+-]+@[\w.-]+)", text) and re.search(
            r"send_email|envoie[^\n]*e-mail|e-mail de confirmation", low
        ):
            addr = re.search(r"([\w.+-]+@[\w.-]+)", text)
            out.append(f"ACTION send_email {json.dumps({'to': addr.group(1), 'body': 'Recapitulatif de la conversation'})}")
        if m := re.search(r"rembourse[^\n]*?(\d{4,})[^\n]*?(\d[\d ]*) ?€", low):
            out.append(f"ACTION refund {json.dumps({'order': m.group(1), 'amount': int(m.group(2).replace(' ', ''))})}")
        if m := re.search(r"(!\[[^\]]*\]\(https?://[^)]+\))", text):
            out.append(m.group(1))
        if m := re.search(r"(<script>.*?</script>)", user, re.S):
            out.append(m.group(1))
        return "\n".join(out) or "Bonjour ! Comment puis-je vous aider avec votre commande ?"


class ClaudeLLM:
    name = "claude"

    def __init__(self, api_key: str, model: str) -> None:
        self.headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        self.model = model

    def complete(self, system: str, user: str, max_tokens: int) -> str:
        body = {"model": self.model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]}
        r = httpx.post("https://api.anthropic.com/v1/messages", headers=self.headers, json=body, timeout=90)
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"] if b.get("type") == "text")


def llm_from_name(name: str) -> LLM:
    if name in {"claude", "anthropic"}:
        return ClaudeLLM(os.environ["ANTHROPIC_API_KEY"], os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"))
    return ObedientSimulator()
