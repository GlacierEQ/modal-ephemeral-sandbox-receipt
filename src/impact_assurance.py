"""Executable near/far impact assurance for Ephemeral Sandbox Receipt."""
from dataclasses import asdict,dataclass
from math import isfinite
from typing import Iterable
REPOSITORY="modal-ephemeral-sandbox-receipt"; COMPANY_LENS="Modal"; INNOVATION="Ephemeral Sandbox Receipt"
@dataclass(frozen=True,slots=True)
class ImpactVector:
 near_term_value:float; long_term_leverage:float; failure_blast_radius:float; reversibility:float; evidence_strength:float; company_fit:float; cross_repo_compounding:float
 def __post_init__(self):
  for n,v in asdict(self).items():
   if not isfinite(v) or not 0<=v<=10: raise ValueError(f"{n} must be finite and within [0, 10]")
@dataclass(frozen=True,slots=True)
class ImpactAssessment:
 score:float; risk:float; leverage:float; band:str; vector:ImpactVector
 def as_dict(self): return {"repository":REPOSITORY,"company_lens":COMPANY_LENS,"innovation":INNOVATION,"score":self.score,"risk":self.risk,"leverage":self.leverage,"band":self.band,"vector":asdict(self.vector)}
def assess(v:ImpactVector)->ImpactAssessment:
 leverage=.22*v.near_term_value+.22*v.long_term_leverage+.16*v.company_fit+.14*v.evidence_strength+.16*v.cross_repo_compounding+.10*v.reversibility
 containment=(v.reversibility+v.evidence_strength)/20; risk=v.failure_blast_radius*(1-.65*containment); score=max(0,min(10,leverage-.18*risk)); band="COMPOUND" if score>=8 else "ADVANCE" if score>=6 else "HARDEN" if score>=4 else "REWORK"; return ImpactAssessment(round(score,3),round(risk,3),round(leverage,3),band,v)
def rank(vectors:Iterable[ImpactVector]): return sorted((assess(v) for v in vectors),key=lambda a:(a.score,a.leverage),reverse=True)
