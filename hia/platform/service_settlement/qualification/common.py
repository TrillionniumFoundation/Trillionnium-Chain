"""Qualification byte identities and the original public error-code roster."""
import hashlib,json

CODES = ["InvalidContext", "InvalidBounds", "NonCanonical", "IdentifierMismatch",
         "InvalidSignature", "Unauthorized", "StaleVersion", "InvalidTransition",
         "SequenceGap", "RootMismatch", "ArithmeticOverflow", "ConservationViolation",
         "InsufficientFunds", "NotMature", "AlreadyConsumed", "Conflict", "NotFound",
         "StoreFailure", "SchemaMismatch", "TamperDetected", "SidecarPresent",
         "CommitUncertain", "ThirdStateFenced"]

def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
