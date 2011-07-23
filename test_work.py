import proofnet
import hashlib
import base64
import time

pm=proofnet.proof_message()
pm.set_target(b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
pm.set_channel("Proofnet1")
pm.set_message_type("proofnet:text")
pm.set_message_bytes(b"my test message")
pm.nonce=10958290
pm.utc_time=time.time()
pm.proof_hash=hashlib.sha256(b"nothing")
#print(base64.b16encode(pm.get_after_proof_bytes()))
print("get_bytes before work: %s" % base64.b16encode(pm.get_bytes()))
pm.do_work()
print("get_bytes after work: %s" % base64.b16encode(pm.get_bytes()))
print("nonce: %s" % pm.nonce)
print("proof: %s" % (base64.b16encode(pm.proof_hash.digest(),)))
print("target: %s" % (base64.b16encode(pm.target_bytes,)))
