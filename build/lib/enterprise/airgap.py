"""Air-gap mode — offline operation without external APIs (v0.38)."""
import os
from pathlib import Path
from typing import Dict, Optional

def is_airgap() -> bool: return os.environ.get("GSC_AIRGAP","").lower() in ("1","true","yes")

class AirgapConfig:
    def __init__(self, bundle: Optional[str] = None):
        self.bundle_path = Path(bundle or os.environ.get("GSC_VULN_BUNDLE","/data/vuln-bundle"))
        self.enabled = is_airgap()

    def validate(self) -> Dict[str,bool]:
        if not self.enabled: return {"applicable": False}
        return {"applicable": True, "bundle_exists": self.bundle_path.exists(),
                "osv_snapshot": (self.bundle_path/"osv-snapshot.json").exists(),
                "detector_weights": (self.bundle_path/"detector-weights.json").exists()}

    def disabled_services(self) -> Dict[str,bool]:
        return {} if not self.enabled else {"osv_dev": True, "epss_api": True, "deepseek_llm": True, "github_api": False}
