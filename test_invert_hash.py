import proofnet
import hashlib

print(proofnet.invert_hash(hashlib.sha256(b"Proofnet1").digest()))
print(proofnet.invert_hash(hashlib.sha256(b"Unknown hash").digest()))
