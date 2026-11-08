"""Core interfaces and data structures for cryptokit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Candidate:
    """Represents a potential plaintext candidate produced by an attack or decoding step."""

    plaintext: bytes
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    @property
    def text(self) -> str:
        """Return plaintext decoded as UTF-8 with non-decodable bytes replaced."""
        return self.plaintext.decode("utf-8", errors="replace")

    def __repr__(self) -> str:
        snippet = self.text[:50] + ("..." if len(self.text) > 50 else "")
        return f"<Candidate method={self.method!r} score={self.score:.1f} text={snippet!r}>"


class Attack(ABC):
    """Abstract base class for all cryptokit attacks and solvers."""

    name: str = "base_attack"

    @abstractmethod
    def applicable(self, **ctx: Any) -> bool:
        """Return True if the context contains parameters required to execute this attack."""
        raise NotImplementedError

    @abstractmethod
    def run(self, **ctx: Any) -> list[Candidate]:
        """Execute the attack using context parameters and return a list of ranked Candidates."""
        raise NotImplementedError
