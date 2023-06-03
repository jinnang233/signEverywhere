import argon2
import pyspx
import getpass
import base64
import hashlib
import os
import re
import json
import asyncio
from kademlia.network import Server

class SPHApp():
    def __init__(self):
        self.pk = None
        self.sk = None
        self.server = Server()

    async def server_run(self, bootstrap_nodes, port=8470):
        await self.server.listen(port)
        await self.server.bootstrap(bootstrap_nodes)

    async def server_get_value(self, key):
        return await self.server.get(key)

    async def server_set_value(self, key, value):
        await self.server.set(key, value)

    def __del__(self):
        self.server.stop()

    def run(self, bootstrap_nodes, runForever=False, port=8470):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.server_run(bootstrap_nodes, port))
        if runForever:
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.server.stop()
                loop.close()

    def set_value(self, key, value):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.server_set_value(key, value))

    def get_value(self, key):
        loop = asyncio.get_event_loop()
        get_future = asyncio.ensure_future(self.server_get_value(key))
        loop.run_until_complete(get_future)
        return get_future.result()

    @staticmethod
    def get_fingerprint(key_bundle):
        return hashlib.sha512(json.dumps(key_bundle).encode("utf-8")).hexdigest().upper()

    @staticmethod
    def get_pkey_id(key_bundle):
        return hashlib.sha1(json.dumps(key_bundle).encode("utf-8")).hexdigest().upper()

    def store_pkey(self, key_bundle):
        pkey_id = self.get_pkey_id(key_bundle)
        fingerprint = self.get_fingerprint(key_bundle)
        self.set_value(pkey_id, json.dumps(key_bundle))
        return pkey_id, fingerprint

    def get_pkey(self, pkey_id):
        key_bundle = json.loads(self.get_value(pkey_id))
        fingerprint = self.get_fingerprint(key_bundle)
        return key_bundle, fingerprint

    @staticmethod
    def make_key_bundle(pkey, alg, name):
        return {"pkey": base64.b64encode(pkey).decode(), "alg": alg, "name": name}

    @staticmethod
    def change_alg(name):
        global spx
        if name in alg_list:
            spx = spxload(name)
            return True
        return False

    @staticmethod
    def alglist():
        return alg_list

    @staticmethod
    def get_default_alg():
        return default_alg

    def derive(self, password: str, namespace: str, counter: int, return_seed: bool = False):
        pass_salt = argon2.argon2_hash(
            password,
            salt=hashlib.sha512(("%s%d" % (namespace, counter)).encode()).digest(),
            buflen=spx.crypto_sign_SEEDBYTES)
        pk, sk = spx.generate_keypair(pass_salt)
        self.pk = pk
        self.sk = sk
        if return_seed:
            return pass_salt
        else:
            return pk

    def derive_seed(self, seed):
        if len(seed) != spx.crypto_sign_SEEDBYTES:
            return None
        pk, sk = spx.generate_keypair(seed)
        self.pk = pk
        self.sk = sk
        return pk

    @staticmethod
    def PK_pretest(pk):
        return len(pk) == spx.crypto_sign_PUBLICKEYBYTES

    def sign(self, msg):
        if not self.sk:
            return None
        return spx.sign(msg, self.sk)

    def verify(self, msg, sig, pk):
        return spx.verify(msg, sig, pk)

    @staticmethod
    def ioHash(f):
        hasher = hashlib.sha512()
        for block in iter(lambda: f.read(4096), b""):
            hasher.update(block)
        return hasher.digest()

    @staticmethod
    def fileHash(filename):
        if not SPHApp.isValid(filename):
            return None
        with open(filename, "rb") as f:
            return SPHApp.ioHash(f)

    def sign_file(self, filename):
        file_hash = SPHApp.fileHash(filename)
        return self.sign(file_hash)

    def sign_io(self, f):
        io_hash = SPHApp.ioHash(f)
        return self.sign(io_hash)

    def verify_file(self, filename, signature, pk):
        file_hash = SPHApp.fileHash(filename)
        return self.verify(file_hash, signature, pk)

    def verify_io(self, f_file, f_signature, pk):
        file_hash = SPHApp.ioHash(f_file)
        signature = f_signature.read()
        return self.verify(file_hash, signature, pk)

    def clear(self):
        self.sk = None
        self.pk = None

    @staticmethod
    def isValid(filename):
        return os.path.isfile(filename)
