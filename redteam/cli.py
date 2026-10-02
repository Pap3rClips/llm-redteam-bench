from __future__ import annotations

import argparse
from pathlib import Path

from targets.support_agent import SECRETS, SupportAgent

from .llm import llm_from_name
from .report import compare, to_json, to_markdown
from .runner import load_attacks, run_suite


def main() -> None:
    p = argparse.ArgumentParser(prog="redteam", description="Banc de red teaming LLM (OWASP Top 10)")
    p.add_argument("--attacks", default="attacks/owasp_top10.yaml")
    p.add_argument("--model", default="simulateur", help="simulateur | claude")
    p.add_argument("--profile", default="hardened", choices=["naive", "hardened"])
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--out", default="out")
    p.add_argument("--compare", action="store_true", help="attaque les profils naïf ET durci et compare")
    p.add_argument("--fail-over", type=float, default=None, help="code d'erreur si l'ASR global dépasse ce seuil")
    args = p.parse_args()

    attacks = load_attacks(args.attacks)
    llm = llm_from_name(args.model)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.compare:
        rows = {prof: run_suite(attacks, SupportAgent(llm, prof).ask, SECRETS, args.trials) for prof in ("naive", "hardened")}
        (out / "comparatif.md").write_text(compare(rows), encoding="utf-8")
        for prof, res in rows.items():
            (out / f"rapport_{prof}.md").write_text(to_markdown(res, f"support_agent[{prof}]", llm.name), encoding="utf-8")
        naive = sum(r.successes for r in rows["naive"]) / sum(len(r.trials) for r in rows["naive"])
        hard = sum(r.successes for r in rows["hardened"]) / sum(len(r.trials) for r in rows["hardened"])
        print(f"ASR naïf : {naive:.0%}  →  ASR durci : {hard:.0%}  ({out}/comparatif.md)")
        results = rows["hardened"]
    else:
        results = run_suite(attacks, SupportAgent(llm, args.profile).ask, SECRETS, args.trials)
        (out / "rapport.md").write_text(to_markdown(results, f"support_agent[{args.profile}]", llm.name), encoding="utf-8")
        (out / "rapport.json").write_text(to_json(results), encoding="utf-8")
        asr = sum(r.successes for r in results) / sum(len(r.trials) for r in results)
        print(f"{len(attacks)} attaques · modèle {llm.name} · profil {args.profile} · ASR {asr:.0%} → {out}/rapport.md")

    if args.fail_over is not None:
        asr = sum(r.successes for r in results) / sum(len(r.trials) for r in results)
        if asr > args.fail_over:
            raise SystemExit(f"ASR {asr:.0%} au-dessus du seuil {args.fail_over:.0%}")


if __name__ == "__main__":
    main()
