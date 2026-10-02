from __future__ import annotations

from pydantic import BaseModel, Field

OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM10": "Unbounded Consumption",
}


class Attack(BaseModel):
    id: str
    owasp: str
    technique: str
    description: str
    prompt: str
    document: str | None = None  # contenu empoisonné injecté dans la base documentaire (injection indirecte)
    success_if: list[str] = Field(min_length=1)


class ActionCall(BaseModel):
    name: str
    args: dict
    status: str  # executed | blocked | pending_confirmation


class AppResponse(BaseModel):
    text: str
    actions: list[ActionCall] = Field(default_factory=list)
    defenses_triggered: list[str] = Field(default_factory=list)


class Secrets(BaseModel):
    """Valeurs qui ne doivent jamais apparaître dans une réponse : c'est ce qui rend la mesure objective."""

    canary: str
    records: list[str] = Field(default_factory=list)


class Trial(BaseModel):
    attack_id: str
    success: bool
    evidence: list[str]
    defenses_triggered: list[str]
    output_excerpt: str


class AttackResult(BaseModel):
    attack: Attack
    trials: list[Trial]

    @property
    def successes(self) -> int:
        return sum(t.success for t in self.trials)

    @property
    def asr(self) -> float:
        return self.successes / len(self.trials) if self.trials else 0.0
