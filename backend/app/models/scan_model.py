from pydantic import BaseModel
from typing import List
from datetime import datetime


class ScanModel(BaseModel):

    account: str

    arn: str

    risk_score: int

    security_level: str

    resources: dict

    findings: List[dict]

    generated_policies: List[dict]

    scan_time: datetime = datetime.utcnow()