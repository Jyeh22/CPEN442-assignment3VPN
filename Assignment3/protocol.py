import random
import sys
from typing import Set
from Crypto.Cipher import AES
from hashlib import sha256
from base64 import b64encode, b64decode
import json
from datetime import datetime

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.g = 2
        self.p = 1795591276927160513869333405184131583643627306475609669492396177
        self._private_key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self._private_key = (self.g**random.randint(1, 9999)) % self.p
        timestamp = datetime.now().timestamp()

        message = {'key': self._private_key, 'timestamp': timestamp}
        message_encrypted = self.EncryptAndProtectMessage(json.dumps(message))
        message_encrypted['isProtocol'] = True
        return message_encrypted


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return message['isProtocol']


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        try:
            message_decrypted_json = self.DecryptAndVerifyMessage(message)
            message_decrypted = json.loads(message_decrypted_json)

            if (not self.validTimestamp(message_decrypted['timestamp'])):
                raise Exception("Error: Invalid timestamp")
            if (self._private_key == None):     # receiving 1st response
                response = self.GetProtocolInitiationMessage()
                key = self._private_key * message_decrypted['key']
                self.SetSessionKey(str(key))
                self._private_key = None
                return response
            else:                               # receiving 2nd response
                key = self._private_key * message_decrypted['key']
                self.SetSessionKey(str(key))
                self._private_key = None
                return None

        except Exception as e:
            print (e, e.args)
            raise Exception("Error: Authentication failed")

    def validTimestamp(self, timestamp):
        min_time = timestamp = datetime.now().timestamp() - 120
        max_time = timestamp = datetime.now().timestamp()
        return (timestamp >= min_time ) and (timestamp <= max_time )
    
    # Setting the key for the current session
    def SetSessionKey(self, key):
        print(key)
        self._key = sha256(key.encode('utf-8')).digest()    # ensures key matches 256 bits needed for AES
        return

    # Setting shared secret on TCP connection
    def setSharedSecret(self, key):
        self.SetSessionKey(key)
        return
   
    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        try:
            cipher = AES.new(self._key, AES.MODE_EAX)
            cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
            nonce = cipher.nonce

            result = {'cipher_text': b64encode(cipher_text).decode('utf-8'), 'tag': b64encode(tag).decode('utf-8'), 'nonce': b64encode(nonce).decode('utf-8'), 'isProtocol': False}       
            return result
        except:
            raise Exception("Error: INTEGRITY VERIFICATION OR AUTHENTICATION FAILED")    



    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text ):     
        try:
            json_keys = ['cipher_text', 'tag', 'nonce']
            encrypted_message = {key:b64decode(cipher_text[key]) for key in json_keys}

            cipher = AES.new(self._key, AES.MODE_EAX, nonce=encrypted_message['nonce'])
            plain_text = cipher.decrypt_and_verify(encrypted_message['cipher_text'], encrypted_message['tag'])
            return plain_text    
        except ValueError:     
            raise Exception("Error: INTEGRITY VERIFICATION OR AUTHENTICATION FAILED") 