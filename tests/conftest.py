import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redteam.llm import ObedientSimulator  # noqa: E402
from redteam.runner import load_attacks  # noqa: E402
from targets.support_agent import SECRETS, SupportAgent  # noqa: E402


@pytest.fixture(scope="session")
def attacks():
    return load_attacks(ROOT / "attacks" / "owasp_top10.yaml")


@pytest.fixture
def secrets():
    return SECRETS


@pytest.fixture
def naive():
    return SupportAgent(ObedientSimulator(), "naive")


@pytest.fixture
def hardened():
    return SupportAgent(ObedientSimulator(), "hardened")
