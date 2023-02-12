import pytest
import asyncio
import random
import uuid
import os
import json
from signEverywhere import sphapp
class TestSignEverywhere:
    def test_server_dht(self):
        app = sphapp.SPHApp()
        node_list = [("127.0.0.1",8468)]
        app.run(node_list)
        num = random.randint(1,100)
        key = "test_uuid_" + str(uuid.uuid1().int)
        app.set_value(key,num)
        assert int(app.get_value(key)) is num
    def test_store_and_fetch(self):
        app = sphapp.SPHApp()
        sphapp.SPHApp.change_alg("shake_256f")
        pk = app.derive_seed(os.urandom(96))
        node_list = [("127.0.0.1",8468)]
        app.run(node_list)

        key = app.make_key_bundle(pk,"shake_256f", "zhangsan")
        pkey_id, fingerprint = app.store_pkey(key)
        key_1, fingerprint = app.get_pkey(pkey_id)
        assert app.get_fingerprint(key) == fingerprint

