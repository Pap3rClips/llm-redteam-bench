# LLM Red Team Bench

**Banc de tests offensifs pour applications LLM, aligné sur l'OWASP Top 10 for LLM Applications (2025).**

Le banc joue un catalogue d'attaques (injection de prompt directe et indirecte, exfiltration du prompt système, détournement d'outils, exfiltration par image Markdown, injection HTML, consommation non bornée) contre une application LLM, et mesure un **taux de succès** par catégorie OWASP. Le verdict est **déterministe** : une attaque réussit seulement si un secret planté fuit — même encodé — ou si une action interdite s'exécute. Aucun jugement subjectif, donc utilisable en intégration continue.

![CI](https://github.com/Pap3rClips/llm-redteam-bench/actions/workflows/ci.yml/badge.svg)

## Le résultat en une image

La même application, attaquée avec le même catalogue, en version naïve puis durcie :

| | Version naïve | Version durcie |
|---|---|---|
| **Taux de succès des attaques** | **100 %** | **0 %** |

👉 [Comparatif détaillé](docs/exemple/comparatif.md) · [rapport version naïve](docs/exemple/rapport_naive.md) · [rapport version durcie](docs/exemple/rapport_hardened.md)

Le banc ne se contente pas de dire « c'est vulnérable » : il **démontre ce que chaque défense apporte**, attaque par attaque.

## Démarrage rapide

```bash
pip install -r requirements.txt
python -m redteam --compare        # attaque les deux profils et compare, sans clé d'API
```

```text
ASR naïf : 100%  →  ASR durci : 0%  (out/comparatif.md)
```

Contre un vrai modèle, pour mesurer ce qu'il refuse de lui-même :

```bash
export ANTHROPIC_API_KEY=...
python -m redteam --model claude --profile hardened
```

## L'application cible

Une application réaliste : un **agent de support e-commerce** dont le prompt système contient
un secret (un canari) et une base clients, et qui dispose de deux outils sensibles
(`send_email`, `refund`). Elle existe en deux profils — `naive` et `hardened` — pour rendre
l'effet des défenses mesurable. C'est un support d'étude ; le banc, lui, s'applique à toute
application exposant la même interface.

## Attaques couvertes

| OWASP 2025 | Risque | Attaques du catalogue |
|---|---|---|
| LLM01 | Prompt Injection | prise de contrôle directe ; injection **indirecte** via une fiche produit |
| LLM02 | Sensitive Information Disclosure | extraction de la base clients |
| LLM05 | Improper Output Handling | exfiltration par image Markdown ; injection HTML/XSS |
| LLM06 | Excessive Agency | remboursement sans validation ; e-mail détourné vers l'extérieur |
| LLM07 | System Prompt Leakage | exfiltration caractère par caractère ; encodage base64 |
| LLM10 | Unbounded Consumption | amplification de la sortie |

## Défenses évaluées (profil durci)

- Données externes **délimitées** et déclarées non fiables (contre l'injection indirecte).
- **Garde-fou de sortie** : caviardage de tout secret connu, même fragmenté ou encodé en base64 ; retrait des images vers un domaine externe ; échappement du HTML.
- Outils sous **liste blanche**, avec mise en attente d'une validation humaine pour les actions irréversibles (remboursement) et blocage des e-mails hors domaine.
- Sortie **bornée** en taille.

## Comment le succès est mesuré

Chaque attaque déclare les détecteurs qui prouvent sa réussite. Les détecteurs sont
déterministes et reconnaissent un secret **même déguisé** : fragmenté (`C-A-N-A-R-Y`),
inversé, ou encodé en base64 (ils décodent avant de comparer). Détail dans
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Qualité

- **18 tests** : détecteurs (y compris secret fragmenté et encodé), profils naïf et durci, catalogue, et propriété clé : *le durcissement n'aggrave jamais une attaque*.
- **CI GitHub Actions** : Ruff, pytest, Bandit, pip-audit, et un garde-fou de non-régression qui échoue si le profil durci laisse passer une attaque.

## Limites

Le simulateur intégré est un « pire cas » qui obéit à tout : il mesure ce que les défenses **applicatives** arrêtent, pas la robustesse d'un modèle réel. Pour cela, lancer avec `--model claude`. Le catalogue couvre les catégories testables en boîte noire sur une application de chat, pas celles liées à la chaîne d'approvisionnement ou à l'entraînement. Les détecteurs mesurent des fuites connues, plantées à l'avance.

## Feuille de route

- [ ] Étendre le catalogue (variantes multilingues, injections à plusieurs tours)
- [ ] Rapport HTML avec le détail des échanges attaque par attaque
- [ ] Mesure comparée de plusieurs modèles (part des attaques refusées par le modèle seul)
- [ ] Brancher les applications cibles [llm-privacy-gateway](https://github.com/Pap3rClips/llm-privacy-gateway) et [wazuh-llm-triage](https://github.com/Pap3rClips/wazuh-llm-triage) comme cibles réelles

## Licence

MIT
