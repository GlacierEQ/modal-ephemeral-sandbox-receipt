from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from ephemeral_sandbox_receipt import Decision, EphemeralSandboxReceipt, EphemeralSandboxReceiptRequest


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def demo_payload() -> dict:
    return {"mode":"attest","run_id":"run-demo","input_digest":_sha("input"),"resource_limits":{"cpu_seconds":5.0,"memory_mb":512.0,"network_bytes":2048.0,"wall_seconds":10.0,"output_bytes":1024.0},"observed_run":{"cpu_seconds":2.0,"memory_mb":256.0,"network_bytes":1024.0,"wall_seconds":3.0,"output_bytes":128.0,"exit_code":0,"output_digest":_sha("output"),"final_fs_digest":_sha("fs"),"network_destinations":["api.example.com"],"revoked_capabilities":["secret:token","network"],"filesystem_destroyed":True},"allowed_network_destinations":["api.example.com"],"required_revocations":["secret:token","network"],"allowed_exit_codes":[0]}


def main() -> int:
    parser=argparse.ArgumentParser(description="Attest or verify an ephemeral sandbox run")
    parser.add_argument("--input",type=Path)
    parser.add_argument("--subject",default="sandbox-demo")
    args=parser.parse_args()
    payload=json.loads(args.input.read_text()) if args.input else demo_payload()
    receipt=EphemeralSandboxReceipt().evaluate(EphemeralSandboxReceiptRequest(args.subject,payload,1.0))
    print(json.dumps(receipt.as_dict(),indent=2,sort_keys=True))
    return 0 if receipt.decision is Decision.ALLOW else 2

if __name__=="__main__":
    raise SystemExit(main())
