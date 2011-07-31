import unittest
import hashlib
import proofnet

class test_proof_message(unittest.TestCase):
	def test_set_target_nzeros(self):
		pn=proofnet.proof_message()
		pn.set_target_nzeros(8)
		self.assertEqual(pn.target, b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		pn.set_target_nzeros(16)
		self.assertEqual(pn.target, b'\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		pn.set_target_nzeros(4)
		self.assertEqual(pn.target, b'\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		pn.set_target_nzeros(48)
		self.assertEqual(pn.target,b'\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		pn.set_target_nzeros(7)
		self.assertEqual(pn.target, b'\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')

	def test_set_and_get_target_nzeros(self):
		pn=proofnet.proof_message()
		pn.set_target_nzeros(8)
		self.assertEqual(pn.get_target_nzeros(),8)
		pn.set_target_nzeros(50)
		self.assertEqual(pn.get_target_nzeros(),50)
		pn.set_target_nzeros(4)
		self.assertEqual(pn.get_target_nzeros(),4)
		pn.set_target_nzeros(32)
		self.assertEqual(pn.get_target_nzeros(),32)
		pn.set_target(b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		self.assertEqual(pn.get_target_nzeros(),8)
		pn.set_target(b'\x00\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		self.assertEqual(pn.get_target_nzeros(),8)

	def test_invert_hash_success(self):
		mytext="proofnet:text"
		inverted=proofnet.invert_hash(hashlib.sha256(mytext.encode()).digest())
		self.assertEqual(mytext,inverted)
	
	def test_invert_hash_fail(self):
		mytext="not a known hash"
		inverted=proofnet.invert_hash(hashlib.sha256(mytext.encode()).digest())
		self.assertEqual(False,inverted)

	def test_encode_decode(self):
		channel="proofnet"
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

class proof_message_text_test(unittest.TestCase):
	def test_init(self):
		pn=proofnet.proof_message_text()
		self.assertEqual("proofnet:text", pn.message_type)

	def test_set_get_message(self):
		pn=proofnet.proof_message_text()
		mytext="this is my test text"
		pn.set_text(mytext)
		self.assertEqual(mytext, pn.get_text())

if __name__=="__main__":
	unittest.main()
