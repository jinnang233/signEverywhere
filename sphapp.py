import argon2
import pyspx
import pyspx.shake_256f
import getpass
import base64
import hashlib
import os


class SPHApp():
    def __init__(self):
        self.pk = None
        self.sk = None
    def derive(self,password:str, namespace:str, counter:int):
        pass_salt = argon2.argon2_hash(
            password,
            salt=hashlib.sha512(("%s%d" % (namespace,counter)).encode()).digest(),
            buflen=96)
        pk,sk = pyspx.shake_256f.generate_keypair(pass_salt)
        self.pk = pk
        self.sk = sk
        return pk
    def sign(self,msg):
        if not self.sk:
            return None
        return pyspx.shake_256f.sign(msg,self.sk)
    def verify(self,msg,sig,pk):
        return pyspx.shake_256f.verify(msg,sig,pk)
    def fileHash(filename):
        if not SPHApp.isValid(filename):
            return None
        hasher = hashlib.sha512()
        with open(filename,"rb") as f:
            while True:
                block = f.read(4096)
                if not block:
                    break
                hasher.update(block)
        return hasher.digest()
    def sign_file(self,filename):
        file_hash = SPHApp.fileHash(filename)
        return self.sign(file_hash)
    def verify_file(self,filename, signature,pk):
        file_hash = SPHApp.fileHash(filename)
        return self.verify(file_hash,signature,pk)
            
    def clear(self):
        self.__init__()
    def isValid(filename):
        valid = True
        if not os.path.exists(filename):
            valid = False
        if os.path.isdir(filename):
            valid = False
        
        return valid
