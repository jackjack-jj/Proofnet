import unittest
import hashlib
import proofnet

class proofnet_test(unittest.TestCase):
	def testInvertHashSuccess(self):
		mytext="proofnet:text"
		inverted=proofnet.invert_hash(hashlib.sha256(mytext.encode()).digest())
		self.assertEqual(mytext,inverted)
	
	def testInvertHashFail(self):
		mytext="not a known hash"
		inverted=proofnet.invert_hash(hashlib.sha256(mytext.encode()).digest())
		self.assertEqual(False,inverted)

	def testEncodeDecode(self):
		channel="proofnet.1"
		message_type="proofnet:text"
		message="My UTF-8 text message."
		pm=proofnet.proof_message()
		pm.set_channel(channel)
		pm.set_message_type(message_type)
		pm.set_message(message.encode())
		pm.do_work()
		pm2=proofnet.proof_message()
		pm2.decode_from_bytes(pm.get_bytes())
		self.assertEqual(pm2.message.decode('utf-8'),message)
		self.assertEqual(pm2.channel,channel)
		self.assertEqual(pm2.message_type,message_type)

if __name__=="__main__":
	unittest.main()
