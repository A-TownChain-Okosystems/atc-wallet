# Compatibility shim.
# The canonical implementation is wallet.ecdsa; this legacy path is kept
# import-compatible but contains no independent runtime implementation.
from wallet.ecdsa import ECDSASigner

__all__ = ["ECDSASigner"]
