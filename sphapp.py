import argon2
import pyspx
import getpass
import base64
import hashlib
import os
import re

alg_list = list(filter(lambda a:len(re.findall("[^_]+?\_[^_]+?\.py",a))!=0,os.listdir(pyspx.__path__[0])))
alg_list = [i.rstrip(".py") for i in alg_list]
spxload = lambda x: __import__("pyspx.{}".format(x),fromlist=[None])
spx = spxload("shake_256f")


class SPHApp():
    def __init__(self):
        self.pk = None
        self.sk = None
    def change_alg(name):
        global spx
        if name in alg_list:
            spx = spxload(name)
            return True
        return False
    def alglist():
        global alg_list
        return alg_list
    def derive(self,password:str, namespace:str, counter:int):
        pass_salt = argon2.argon2_hash(
            password,
            salt=hashlib.sha512(("%s%d" % (namespace,counter)).encode()).digest(),
            buflen=spx.crypto_sign_SEEDBYTES)
        pk,sk = spx.generate_keypair(pass_salt)
        self.pk = pk
        self.sk = sk
        return pk
    def PK_pretest(pk):
        if len(pk) != spx.crypto_sign_PUBLICKEYBYTES:
            return False
        return True
    def sign(self,msg):
        if not self.sk:
            return None
        return spx.sign(msg,self.sk)
    def verify(self,msg,sig,pk):
        return spx.verify(msg,sig,pk)
    def ioHash(f):
        hasher = hashlib.sha512()
        while True:
            block = f.read(4096)
            if not block:
                break
            hasher.update(block)
        return hasher.digest()
    def fileHash(filename):
        if not SPHApp.isValid(filename):
            return None
        with open(filename,"rb") as f:
            return SPHApp.ioHash(f)
    def sign_file(self,filename):
        file_hash = SPHApp.fileHash(filename)
        return self.sign(file_hash)
    def sign_io(self,f):
        io_hash = SPHApp.ioHash(f)
        return self.sign(io_hash)
    def verify_file(self,filename, signature,pk):
        file_hash = SPHApp.fileHash(filename)
        return self.verify(file_hash,signature,pk)
    def verify_io(self,f_file,f_signature, pk):
        file_hash = SPHApp.ioHash(f_file)
        signature = f_signature.read()
        return self.verify(file_hash,signature, pk)
    def clear(self):
        self.__init__()
    def isValid(filename):
        valid = True
        if not os.path.exists(filename):
            valid = False
        if os.path.isdir(filename):
            valid = False
        
        return valid
