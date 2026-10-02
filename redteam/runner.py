"""Exécute le catalogue d'attaques contre une application cible et mesure le taux de succès."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from .detectors import DETECTORS
from .models import Attack, AttackResult, Secrets, Trial


def load_attacks(path: str | Path) -> list[Attack]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [Attack(**a) for a in data]


def run_attack(attack: Attack, ask: Callable[..., object], secrets: Secrets, trials: int) -> AttackResult:
    results = []
    for _ in range(trials):
        resp = ask(attack.prompt, attack.document)
        evidence: list[str] = []
        for name in attack.success_if:
            evidence += DETECTORS[name](resp, secrets)
        results.append(
            Trial(
                attack_id=attack.id,
                success=bool(evidence),
                evidence=evidence,
                defenses_triggered=resp.defenses_triggered,
                output_excerpt=resp.text[:280],
            )
        )
    return AttackResult(attack=attack, trials=results)


def run_suite(attacks: list[Attack], ask: Callable[..., object], secrets: Secrets, trials: int = 1) -> list[AttackResult]:
    return [run_attack(a, ask, secrets, trials) for a in attacks]
