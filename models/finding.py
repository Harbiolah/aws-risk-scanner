from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class Finding:
    resource_id: str
    resource_type: str
    rule_id: str
    title: str
    description: str
    severity: str
    impact: int
    likelihood: int
    exposure: int
    asset_sensitivity: int

    def risk_score(self) -> float:
        w1, w2, w3, w4 = 0.35, 0.25, 0.20, 0.20
        score = (
            self.impact * w1
            + self.likelihood * w2
            + self.exposure * w3
            + self.asset_sensitivity * w4
        )
        return round(score, 2)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_score"] = self.risk_score()
        return data
