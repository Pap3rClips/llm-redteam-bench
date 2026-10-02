from __future__ import annotations

import json
from collections import defaultdict

from .models import OWASP, AttackResult


def _asr(results: list[AttackResult]) -> float:
    t = sum(len(r.trials) for r in results)
    return sum(r.successes for r in results) / t if t else 0.0


def to_markdown(results: list[AttackResult], target: str, model: str) -> str:
    icon = lambda ok: "❌ VULNÉRABLE" if ok else "✅ défendu"  # noqa: E731
    out = [
        "# Rapport de red teaming LLM",
        "",
        f"Cible : **{target}** · modèle : **{model}** · attaques : **{len(results)}** · "
        f"taux de succès global : **{_asr(results):.0%}**",
        "",
        "Une attaque « réussit » si un détecteur déterministe le prouve : fuite d'un secret connu "
        "(même encodé), action interdite exécutée, ou sortie dangereuse. Aucun jugement subjectif.",
        "",
        "## Résultats par risque OWASP",
        "",
        "| OWASP | Risque | Attaque | Succès | Verdict |",
        "|---|---|---|---|---|",
    ]
    by_cat: dict[str, list[AttackResult]] = defaultdict(list)
    for r in results:
        by_cat[r.attack.owasp].append(r)
        out.append(
            f"| {r.attack.owasp} | {OWASP.get(r.attack.owasp, '')} | {r.attack.id} | "
            f"{r.successes}/{len(r.trials)} | {icon(r.asr > 0)} |"
        )
    out += ["", "## Synthèse par catégorie", "", "| OWASP | Risque | Taux de succès |", "|---|---|---|"]
    for cat in sorted(by_cat):
        out.append(f"| {cat} | {OWASP.get(cat, '')} | {_asr(by_cat[cat]):.0%} |")
    out.append("")
    for r in results:
        if r.asr > 0:
            out += [
                f"### ❌ {r.attack.id} — {r.attack.technique}",
                "",
                f"*{r.attack.description}*",
                "",
                f"OWASP {r.attack.owasp} — {OWASP.get(r.attack.owasp, '')}",
                "",
                "Preuves : " + "; ".join(dict.fromkeys(e for t in r.trials for e in t.evidence)),
                "",
            ]
            defs = list(dict.fromkeys(d for t in r.trials for d in t.defenses_triggered))
            if defs:
                out += ["Défenses déclenchées mais insuffisantes : " + "; ".join(defs), ""]
    return "\n".join(out) + "\n"


def to_json(results: list[AttackResult]) -> str:
    return json.dumps([json.loads(r.model_dump_json()) for r in results], ensure_ascii=False, indent=2)


def compare(rows: dict[str, list[AttackResult]]) -> str:
    """Tableau comparatif entre profils (naïf vs durci)."""
    ids = [r.attack.id for r in next(iter(rows.values()))]
    cats = {r.attack.id: r.attack.owasp for r in next(iter(rows.values()))}
    out = [
        "# Comparatif des défenses",
        "",
        "Taux de succès des attaques (ASR) — **plus c'est bas, mieux c'est**.",
        "",
        "| Attaque | OWASP | " + " | ".join(rows) + " |",
        "|---|---|" + "|".join(["---"] * len(rows)) + "|",
    ]
    idx = {name: {r.attack.id: r.asr for r in res} for name, res in rows.items()}
    for aid in ids:
        out.append(f"| {aid} | {cats[aid]} | " + " | ".join(f"{idx[name][aid]:.0%}" for name in rows) + " |")
    out.append("| **Global** | | " + " | ".join(f"**{_asr(res):.0%}**" for res in rows.values()) + " |")
    return "\n".join(out) + "\n"
