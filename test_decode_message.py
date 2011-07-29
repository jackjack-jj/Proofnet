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

print("base16 encoded proofnet message: %s" % base64.b16encode(pm.get_bytes()))
pm2=proofnet.proof_message()
pm2.decode_from_bytes(pm.get_bytes())
print("decoded proof: %s" % base64.b16encode(pm2.proof_hash))
print("decoded nonce: %s" % pm2.nonce)
print("decoded time: %s" % pm2.utc_time)
print("decoded channel: %s" % pm2.channel.decode('utf-8'))
print("decoded message type: %s" % pm2.message_type.decode('utf-8'))
print("decoded message: %s" % pm2.message.decode('utf-8'))

