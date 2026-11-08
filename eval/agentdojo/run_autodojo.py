"""`eval.agentdojo.run` with AutoDojo's optimized injections registered as `--attack autodojo` (see autodojo.py).

    AUTODOJO_VARIANTS=<AutoDojo>/agentdojo/variant_generation/variants \
    AUTODOJO_CELL=deepseek/deepseek-v4-flash/spotlighting \
    python -m eval.agentdojo.run_autodojo --attack autodojo --suites banking,slack,travel --mode attack ...
"""
import sys

from . import autodojo  # noqa: F401  (registers the attack)
from .run import main

if __name__ == "__main__":
    sys.exit(main())
