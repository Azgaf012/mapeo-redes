"""Combine independent pieces of evidence into one identification with a confidence.

Every source (existing fingerprint, vendor driver, mDNS name, OUI role, user
override...) adds an ``Evidence``. Per device type the score is the strongest
weight plus a bounded bonus for corroborating sources; the best type wins. Nothing
is "guessed" below ``MIN_SCORE``: such hosts stay ``UNKNOWN`` and are reported.
"""

from dataclasses import dataclass, field

MIN_SCORE = 15
HIGH, MEDIUM = 80, 50


@dataclass
class Evidence:
    source: str
    weight: int
    device_type: str = None     # None: informative only (vendor/model without a type)
    vendor: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    hostname: str = ""
    detail: str = ""


@dataclass
class Identity:
    device_type: str = "UNKNOWN"
    score: int = 0
    confidence: str = "none"          # high | medium | low | none
    source: str = ""
    sources: list = field(default_factory=list)
    vendor: str = ""
    vendor_weight: int = 0
    model: str = ""
    model_weight: int = 0
    serial: str = ""
    firmware: str = ""
    hostname: str = ""
    evidence: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


def confidence_for(score):
    if score >= HIGH:
        return "high"
    if score >= MEDIUM:
        return "medium"
    return "low" if score >= MIN_SCORE else "none"


def resolve(evidences):
    by_type = {}
    for item in evidences:
        if item.device_type and item.weight > 0:
            by_type.setdefault(item.device_type, []).append(item)

    scored = []
    for device_type, items in by_type.items():
        weights = sorted((item.weight for item in items), reverse=True)
        scored.append((weights[0] + min(20, int(sum(weights[1:]) * 0.3)), weights[0], device_type))
    scored.sort(reverse=True)

    identity = Identity()
    if scored and scored[0][0] >= MIN_SCORE:
        identity.score, _, identity.device_type = scored[0]
        identity.score = min(identity.score, 100)
        identity.confidence = confidence_for(identity.score)
        winners = sorted(by_type[identity.device_type], key=lambda item: -item.weight)
        identity.source = winners[0].source
        identity.sources = [item.source for item in winners]

    # Descriptive fields may come from any evidence, strongest first; evidence
    # for a different type must not rename a device that was identified another way.
    ordered = sorted((item for item in evidences if item.device_type is None or
                      (item.weight > 0 and item.device_type == identity.device_type)),
                     key=lambda item: -item.weight)
    for item in ordered:
        if item.vendor and not identity.vendor:
            identity.vendor, identity.vendor_weight = item.vendor, item.weight
        if item.model and not identity.model:
            identity.model, identity.model_weight = item.model, item.weight
        identity.serial = identity.serial or item.serial
        identity.firmware = identity.firmware or item.firmware
        identity.hostname = identity.hostname or item.hostname
    identity.evidence = [{"source": item.source, "type": item.device_type, "weight": item.weight,
                          "detail": item.detail} for item in
                         sorted(evidences, key=lambda item: -item.weight)[:8] if item.weight > 0]
    return identity
