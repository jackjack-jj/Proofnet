import proofnet
import base64

target=b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
channel="proofnet"
message_type="proofnet:text"
message="My UTF-8 text message."

pm=proofnet.proof_message()
pm.set_target(target)
pm.set_channel(channel)
pm.set_message_type(message_type)
pm.set_message(message.encode())
pm.do_work()
print("target: %s" % base64.b16encode(target))
print("proof: %s" % base64.b16encode(pm.proof_hash))
print("nonce: %s" % pm.nonce)
print("utc time: %s" % pm.utc_time)
print("channel: %s" % pm.channel)
print("message type: %s" % pm.message_type)
print("message bytes: %s" % pm.message)
print("base16 encoded proofnet message: %s" % base64.b16encode(pm.get_bytes()))
