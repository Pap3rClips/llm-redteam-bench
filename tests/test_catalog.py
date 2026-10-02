from redteam.models import OWASP


def test_catalogue_valide(attacks):
    assert len(attacks) >= 10
    for a in attacks:
        assert a.owasp in OWASP
        assert a.success_if


def test_categories_couvertes(attacks):
    covered = {a.owasp for a in attacks}
    for cat in ("LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM10"):
        assert cat in covered, cat


def test_ids_uniques(attacks):
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))
