# signEverywhere

You can always have the same secret key and public key by entering same password, namespace and counter. 

## Usage
```
usage: signEverywhere [-h] [--encoding {base64,hex,base32}] [--showpub] [--qr] [--password PASSWORD] [--namespace NAMESPACE] [-c COUNTER]
                      [-a {sha2_256f,haraka_128s,shake_256f,sha2_192s,shake_192s,sha2_128f,shake_256s,sha2_128s,sha2_256s,shake_128s,haraka_128f,haraka_256f,sha2_192f,haraka_192f,shake_128f,haraka_256s,haraka_192s,shake_192f}]
                      {sign,verify} ...

Sign and verify file or message with SPHINCS

positional arguments:
  {sign,verify}
    sign                Sign
    verify              Verify

options:
  -h, --help            show this help message and exit

Key group:
  --encoding {base64,hex,base32}
                        Choose encoding of public key
  --showpub             Show public key
  --qr, --qrcode        Output qrcode
  --password PASSWORD   Password to derive key
  --namespace NAMESPACE
                        Namespace to derive key
  -c COUNTER, --counter COUNTER
                        Counter to derive key
  -a {sha2_256f,haraka_128s,shake_256f,sha2_192s,shake_192s,sha2_128f,shake_256s,sha2_128s,sha2_256s,shake_128s,haraka_128f,haraka_256f,sha2_192f,haraka_192f,shake_128f,haraka_256s,haraka_192s,shake_192f}, --alg {sha2_256f,haraka_128s,shake_256f,sha2_192s,shake_192s,sha2_128f,shake_256s,sha2_128s,sha2_256s,shake_128s,haraka_128f,haraka_256f,sha2_192f,haraka_192f,shake_128f,haraka_256s,haraka_192s,shake_192f}, --algorithm {sha2_256f,haraka_128s,shake_256f,sha2_192s,shake_192s,sha2_128f,shake_256s,sha2_128s,sha2_256s,shake_128s,haraka_128f,haraka_256f,sha2_192f,haraka_192f,shake_128f,haraka_256s,haraka_192s,shake_192f}
                        Algorithm of sphincs [Default: shake_256f]
```
  
  ## Demo
  
  #### Sign
  ```bash
	$ SPassword="password" SNamespace="namespace" SCounter="1" python3 main.py --showpub sign -f ~/test/test -o ~/test/test.sig 
	# Public Key: FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
  ```
  
  #### Verify
  ```bash
	$ python3 main.py verify -f ~/test/test -s ~/test/test.sig -p FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
	#Valid

  ```
