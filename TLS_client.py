# -*- coding: utf-8 -*-

import sys
import os
import time
import datetime
import socket
import random
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TLS_client:
	def request(self,host,port):
		# Open a connection to the server 
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, int(port))) 


		#send ClientHello
		print("CONNECTED")
		client_hello = self.ClientHello()
		s.send(client_hello)


		#Receives reply over TCP from server
		reply = s.recv(2048)


		#ServerHello
		hello_len = int.from_bytes(reply[3:5],'big') #get length of Serverhello 
		ServerHello = reply[5:5+hello_len]
		self.server_random = ServerHello[6:38]

		# 0x00,0x67 - TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
		# 0x00,0x6B - TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
		self.Cipher_Suite = ServerHello[39:41]  
		if self.Cipher_Suite.hex() == '0067':
			print("Cipher Suite used: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256")
		elif self.Cipher_Suite.hex() == '006b':
			print("Cipher Suite used: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")
		else:
			print("Error: TLS_DHE_RSA_WITH_AES_XXX_CBC_SHA256 is not supported by Server!", file=sys.stderr)
			s.close()
			exit()
		print("---")


		#certificate
		cert_begin = 5+hello_len #begin byte of certificate
		cert_len = int.from_bytes(reply[cert_begin+3:cert_begin+5],'big') #get length of certificate
		cert_content = reply[cert_begin+5:cert_begin+5+cert_len]
		certificate = cert_content[10:]

		#verify certificate, close connection if false
		try:
			cert = x509.load_der_x509_certificate(certificate, default_backend())
			#verify date
			c_not_valid_before = cert.not_valid_before
			c_not_valid_after = cert.not_valid_after
			# print(c_not_valid_before)
			# print(c_not_valid_after)
			# print(datetime.datetime.now())
			
			# verify openssl certificate time
			#if you generate a cert.pem using openssl immediately before running the program, this could fail.
			#add one day to now() make time verify pass
			if not (c_not_valid_before < datetime.datetime.now()+datetime.timedelta(days=1) < c_not_valid_after):
				print("Error: Certificate out of date!", file=sys.stderr)
				s.close()
				exit()

			#get certificate public key
			c_public_key = cert.public_key()
			c_issuer = cert.issuer
			c_subject = cert.subject

			#verify certificate
			c_public_key.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
			print("verify certificate return: True")

			print('issuer=%s'%c_issuer)
			print('subject=%s'%c_subject)
			print('---')
		except:
			print("Error: Verify Certificate failed!", file=sys.stderr)
			s.close()
			exit()



		#server key exchange information
		serverkey_begin = cert_begin + 5 + cert_len #begin byte of server key
		key_len = int.from_bytes(reply[serverkey_begin+3:serverkey_begin+5],'big') #get length of key exchange
		key_content = reply[serverkey_begin+5:serverkey_begin+5+key_len]	#get key exchange part information


		#Diffi Halman p
		DH_p_len = int.from_bytes(key_content[4:6],'big')  #get length of DH p
		DH_p_byte = key_content[6:6+DH_p_len]
		DH_p = int.from_bytes(DH_p_byte,'big') #convert binary to DH p


		#Diffi Halman g
		DH_g_begin = 6+DH_p_len
		DH_g_len = int.from_bytes(key_content[DH_g_begin : DH_g_begin+2],'big')  #get length of DH g 
		DH_g_byte = key_content[DH_g_begin+2 : DH_g_begin+2+DH_g_len]
		DH_g = int.from_bytes(DH_g_byte,'big') #convert binary to DH g

		#public key
		ser_pub_key_begin = DH_g_begin+2+DH_g_len
		ser_pub_key_len = int.from_bytes(key_content[ser_pub_key_begin : ser_pub_key_begin+2],'big')  #get length of public key of server
		ser_pub_key = key_content[ser_pub_key_begin+2 : ser_pub_key_begin+2+ser_pub_key_len] #get public key of server
		ser_pk_int = int.from_bytes(ser_pub_key,'big') #convert binary key into an integer



		#signature
		sig_begin = ser_pub_key_begin+2+ser_pub_key_len
		sig_hash = key_content[sig_begin : sig_begin+2] #sha-256
		sig_len = int.from_bytes(key_content[sig_begin+2 : sig_begin+4],'big')
		signature = key_content[sig_begin+4 : sig_begin+4+sig_len]
		
		#verify signature
		#sign on: client_random, server_random, length+DH_p, length+DH_g, length+DH_public
		total_info = self.client_random + self.server_random + key_content[4:sig_begin]
		try:
			c_public_key.verify(signature,total_info,padding.PKCS1v15(),cert.signature_hash_algorithm)
			print("Verify Key exchange signature return: True\n---")
		except:
			print("Error: Verify Key exchange signature failed!", file=sys.stderr)
			s.close()
			exit()
		

		#server hello Done
		hello_begin = serverkey_begin+5+key_len
		server_hello_done = reply[hello_begin:]


		# Client DH key generate
		a = random.randint(0,10000)
		client_DH_key = (DH_g**a) % DH_p


		#ClientKeyExchange
		cke = self.Client_key_Exchange(client_DH_key)
		s.send(cke)

		#Client Encryption keys calculation
		shared_secrct = (ser_pk_int**a) % DH_p

		#client change cipher spec
		ccs = self.client_change_cipher_spec()
		s.send(ccs)

		#client handshake finished
		chf = self.client_handshake_finished(client_hello,ServerHello,cert_content,key_content,server_hello_done,cke,shared_secrct)
		s.send(chf)


		#received 
		try:
			ServerFinish = s.recv(1024)
			#print(ServerFinish.hex())
			#print(len(ServerFinish))
			if ServerFinish.hex()[:2] == '16': #16 indicates successfully received a reply
				print("Server Finished message successfully received!")
			else:
				raise Exception
		except:
			print("Error: Server Finished message not received!", file=sys.stderr)

		'''
		handshake finishes.
		request and receive main content...
		'''
		#close connection
		s.close()



	#Client Hello message
	def ClientHello(self):
		record  = b'\x16\x03\x01' + b'\x00j' 	#108 bytes length after  
		handshake = b'\x01' + b'\x00\x00f' 		#104 bytes length after
		version = b'\x03\x03'			#TLS 1.2
		timestamp = int(time.time()).to_bytes(4,byteorder='big') #now - 4 bytes
		random = os.urandom(28)		#28 bytes random
		ID = b'\x00'				#no seesion ID
		cipher = b'\x00\x04\x00\x67\x00\x6b'
		compression = b'\x01\x00'	#no compression
		extension = b'\x009\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x1c\x00\x1a\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\x0d\x00\x0b\x00\x0c\x00\x09\x00\x0a\x00\x23\x00\x00\x00\x0f\x00\x01\x01'
		signature = b'\x00\x0d\x00\x04\x00\x02\x04\x01' #sha256
		self.client_random = timestamp+random
		return record + handshake + version + timestamp + random + ID + cipher + compression + extension + signature

	#Client key exchange 
	def Client_key_Exchange(self,client_DH_key):
		record = b'\x16\x03\x03' + b'\x00\x86'  	#134 bytes length after
		handshake = b'\x10' + b"\x00\x00\x82" 		#130 bytes length after(public key length)
		public_key = b'\x00\x80' + client_DH_key.to_bytes(128,byteorder='big') #convert integer to 128 bytes 
		return record + handshake + public_key

	#client change cipher spec
	def client_change_cipher_spec(self):
		return b"\x14\x03\x03\x00\x01\x01"

	#client handshake finished
	def client_handshake_finished(self, client_hello, ServerHello, cert_content, key_content, server_hello_done, client_key_exchange, shared_secret):
		#header
		record = b'\x16\x03\x03' + b'\x00\x50'  	#80 bytes length after

		#get master secret
		master_secret = self.derive_master_secret(shared_secret)
		#get the final encryption keys
		self.generate_final_encryption_key(master_secret)

		#Encryption IV
		#iv = self.client_write_IV
		iv = os.urandom(16)		#16 bytes random
		client_key = self.client_write_key
		mac_key = self.client_write_mac_key

		#Encrypted Data
		#handshake header
		handshake_header = b'\x14' + b'\x00\x00\x0c'  #12 bytes verify data

		#verify data		
		#all information sent and received, not include record header
		handshake_messages = client_hello[5:] + ServerHello + cert_content + key_content + server_hello_done[5:] + client_key_exchange[5:]
		seed = b"client finished" + self.hash(handshake_messages)
		#calculate verify data
		a0 = seed
		a1 = self.hmac_256(master_secret, a0)
		p1 = self.hmac_256(master_secret, a1 + seed)
		verify_data = p1[:12]

		#encryption step
		cipher = Cipher(algorithms.AES(client_key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		
		#calculate the last 48 bytes
		sequence=b'\x00\x00\x00\x00\x00\x00\x00\x00'
		hash_content = b'\x16\x03\x03' + b'\x00\x10' + handshake_header + verify_data #record header + length
		hash_code = self.hmac_256(mac_key, sequence+hash_content)

		#total plain-text before encryption
		final_plaintext = handshake_header + verify_data + hash_code + b"\x0f"*16 #add 16 bytes padding 
		
		#encrypt data using AES-CBC
		Encrypted_Data = encryptor.update(final_plaintext) + encryptor.finalize()

		#return record + 80 bytes encryption
		return record + iv + Encrypted_Data
		

	#derive a masetr secret
	def derive_master_secret(self,shared_secrct):
		#variables
		pre_master_secret = shared_secrct.to_bytes(128,byteorder='big').lstrip(b'\x00')
		ms = b"master secret"
		random_data = self.client_random + self.server_random
		
		#calculate master secret
		seed = ms + random_data
		a0 = seed
		a1 = self.hmac_256(pre_master_secret, a0)
		a2 = self.hmac_256(pre_master_secret, a1)
		p1 = self.hmac_256(pre_master_secret, a1+seed)
		p2 = self.hmac_256(pre_master_secret, a2+seed)

		master_secret = p1 + p2[:16] #48 bytes

		return master_secret


	#generate the final encryption keys using a key expansion
	def generate_final_encryption_key(self,master_secret):
		#calculate to get session keys
		seed = b"key expansion" + self.server_random + self.client_random
		a0 = seed
		a1 = self.hmac_256(master_secret, a0)
		a2 = self.hmac_256(master_secret, a1)
		a3 = self.hmac_256(master_secret, a2)
		a4 = self.hmac_256(master_secret, a3)

		p1 = self.hmac_256(master_secret, a1+seed)
		p2 = self.hmac_256(master_secret, a2+seed)
		p3 = self.hmac_256(master_secret, a3+seed)
		p4 = self.hmac_256(master_secret, a4+seed)

		p = p1 + p2 + p3 + p4

		#get all session keys
		self.client_write_mac_key = p[:32]
		self.server_write_mac_key = p[32:64]
		
		#write keys are based on cipher suite
		if self.Cipher_Suite.hex() == '0067':  #AES-128 has 16 bytes write keys
			self.client_write_key = p[64:80]
			self.server_write_key = p[80:96]
			self.client_write_IV = p[96:112]
			self.server_write_IV = p[112:128]
		elif self.Cipher_Suite.hex() == '006b': #AES-256 has 32 bytes write keys
			self.client_write_key = p[64:96]
			self.server_write_key = p[96:128]			


	#using SHA256 to hash a shared secret
	def hash(self, password):
		hash_code = hashlib.sha256()
		hash_code.update(password)
		code = hash_code.digest()
		return code

	#using HMAC with sha256 and key
	def hmac_256(self,key,msg):
		hmac_code = hmac.new(key,msg=None, digestmod=hashlib.sha256)
		hmac_code.update(msg)
		return hmac_code.digest()


#start program
if __name__=="__main__":
	client = TLS_client()
	if len(sys.argv) != 3:
		print("Error! Enter: python TLS_client.py <server_ip> <port>", file=sys.stderr)
		exit()
	else:
		client.request(sys.argv[1],sys.argv[2]) #ip port
