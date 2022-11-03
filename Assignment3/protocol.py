import random
from typing import Set
from Crypto.Cipher import AES
from hashlib import sha256
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import dh
import json
import time

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.DHval = None
        self.g = 2
        self.p = 1795591276927160513869333405184131583643627306475609669492396177
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self.DHval = random.random()
        return (self.g**self.DHval) % self.p


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return True # for testing


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        mess = (message)
        retval = None
        if self.DHval != None :
            self.SetSessionKey((int(mess)**self.DHval)%self.p )
        else:
            self.DHval = random.random()
            self.SetSessionKey((int(mess)**self.DHval)%self.p )
            retval =  (self.g**self.DHval) % self.p
            
        self.DHval = None
        return retval


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = sha256(key.encode('utf-8')).digest()
        return

    # Setting shared secret on TCP connection
    def setSharedSecret(self, key):
        self.SetSessionKey(key)
        return

    # Encrypting messages
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        try:
            cipher = AES.new(self._key, AES.MODE_EAX)
            cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
            nonce = cipher.nonce

            result = {'cipher_text': b64encode(cipher_text).decode('utf-8'), 'tag': b64encode(tag).decode('utf-8'), 'nonce': b64encode(nonce).decode('utf-8')}
            return json.dumps(result)
        except:
            return "Error: INTEGRITY VERIFICATION OR AUTHENTICATION FAILED"   


    # Decrypting and verifying messages
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):     
        try:
            encrypted_message_b64 = json.loads(cipher_text.decode('utf-8'))
            json_keys = ['cipher_text', 'tag', 'nonce']
            encrypted_message = {key:b64decode(encrypted_message_b64[key]) for key in json_keys}

            cipher = AES.new(self._key, AES.MODE_EAX, nonce=encrypted_message['nonce'])
            plain_text = cipher.decrypt_and_verify(encrypted_message['cipher_text'], encrypted_message['tag'])
            return plain_text    
        except ValueError:     
            return "Error: INTEGRITY VERIFICATION OR AUTHENTICATION FAILED"
