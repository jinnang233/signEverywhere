# signEverywhere

You can always have the same secret key and public key by entering same password, namespace and counter. 

## Installation
```bash
$ git clone https://github.com/jinnang233/signEverywhere && cd signEverywhere
$ python3 setup.py install
```

## Usage
```
usage: signEverywhere.py [-h] [--encoding {base64,hex,base32}] [--showpub] [--showseed] [--qr] [--password PASSWORD] [--namespace NAMESPACE] [--seed SEED] [-c COUNTER]
                         [-a {sha2_256f,haraka_128s,shake_256f,sha2_192s,shake_192s,sha2_128f,shake_256s,sha2_128s,sha2_256s,shake_128s,haraka_128f,haraka_256f,sha2_192f,haraka_192f,shake_128f,haraka_256s,haraka_192s,shake_192f}]
                         {sign,verify} ...
```
  
  ## Demo
  
  #### Sign
  ```bash
	SPassword="password" SNamespace="namespace" SCounter="1" python3 -m  signEverywhere.cli --showpub sign -f ~/test/test -o ~/test/test.sig 
	# Public Key: FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
  ```
  
  #### Verify
  ```bash
	python3 -m signEverywhere.cli verify -f ~/test/test -s ~/test/test.sig -p FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
	#Valid

  ```
