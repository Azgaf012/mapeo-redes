"""Evidence-based device identification (drivers + overrides + unidentified report)."""

from scanner.identity.engine import Evidence, Identity, resolve
from scanner.identity.service import IdentityService

__all__ = ["Evidence", "Identity", "IdentityService", "resolve"]
