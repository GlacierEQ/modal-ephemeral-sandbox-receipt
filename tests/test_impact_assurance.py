import unittest
from src.impact_assurance import ImpactVector,assess,rank
class ImpactAssuranceTests(unittest.TestCase):
 def test_compound(self): self.assertEqual(assess(ImpactVector(9,9,4,9,9,9,9)).band,"COMPOUND")
 def test_blast_cost(self): self.assertGreater(assess(ImpactVector(8,8,2,5,5,8,8)).score,assess(ImpactVector(8,8,10,5,5,8,8)).score)
 def test_refuse_invalid(self):
  with self.assertRaises(ValueError): ImpactVector(11,1,1,1,1,1,1)
 def test_rank(self):
  x=rank([ImpactVector(5,5,5,5,5,5,5),ImpactVector(9,9,2,9,9,9,9)]); self.assertGreaterEqual(x[0].score,x[1].score)
