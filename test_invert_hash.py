import proofnet
import hashlib

print(proofnet.invert_hash(hashlib.sha256(b"proofnet").digest()))
print(proofnet.invert_hash(hashlib.sha256(b"Unknown hash").digest()))
