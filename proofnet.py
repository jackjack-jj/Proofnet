import struct
import hashlib
import time

#message format in bytes:
#(proof hash)(nonce)(utc time)(channel hash)(message type hash)(message)

class proof_message:
	def __init__(self):
		self.target_bytes=False
		self.proof_hash=False
		self.nonce=False
		self.utc_time=False
		self.channel=False
		self.channel_hash=False
		self.message_type=False
		self.message_type_hash=False
		self.message_bytes=False
	
	def update_utc_time(self):
		self.utc_time=time.time()
	
	def set_channel(self, channel):
		self.channel=channel
		self.channel_hash=hashlib.sha256(channel.encode())
	
	def set_message_type(self, message_type):
		self.message_type=message_type
		self.message_type_hash=hashlib.sha256(message_type.encode())

	def set_message_bytes(self, message_bytes):
		self.message_bytes=message_bytes
	
	def get_proof_bytes(self):
		return self.proof_hash.digest()

	def get_after_proof_bytes(self):
		b=bytes()
		nonce=int(self.nonce)
		nonce_bytes=struct.pack("L",nonce)
		b+=nonce_bytes
		time=int(self.utc_time)
		time_bytes=struct.pack("L",time)
		b+=time_bytes
		channel_hash_bytes=self.channel_hash.digest()
		b+=channel_hash_bytes
		mtype_hash_bytes=self.message_type_hash.digest()
		b+=mtype_hash_bytes
		return b

	def get_bytes(self):
		return self.get_proof_bytes()+self.get_after_proof_bytes()

	def calc_proof_hash(self):
		b=self.get_after_proof_bytes()
		proof_hash=hashlib.sha256(b)
		self.proof_hash=proof_hash

	def set_target(self, target_bytes):
		self.target_bytes=target_bytes

	def is_hash_less(self, test_hash_bytes, target_bytes):
		"""test_hash_bytes and target_bytes must be bytes, and same length.
		unlike x86 integers, we assume big endian
		"""
		for i in range(0,32):
			if test_hash_bytes[i]<target_bytes[i]:
				return True
			if test_hash_bytes[i]>target_bytes[i]:
				return False
		return False

	def do_work(self):
		target_bytes=self.target_bytes
		progress=0
		while 1:
			for nonce in range(0,1000000):
				progress+=1
				self.update_utc_time()
				self.nonce=nonce
				self.calc_proof_hash()
				testhash_bytes=self.proof_hash.digest()
				if self.is_hash_less(testhash_bytes,self.target_bytes):
					return progress
