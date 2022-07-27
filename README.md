# signEverywhere

You can always have the same secret key and public key by entering same password, namespace and counter. 

```
usage: main.py [-h] [-f FILENAME] [-s SIG] [-o OUT] [-p PK] [--showpub] [--sign] [--verify] [--stdin] [--namespace NAMESPACE] [--password PASSWORD] [-c COUNTER]

Sign and verify file or message with SPHINCS

options:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        File to sign or verify
  -s SIG, --signature SIG
                        Signature file
  -o OUT, --output OUT  Output file
  -p PK, --pubkey PK    Public key
  --showpub             Show public key
  --sign                Sign
  --verify              Verify
  --stdin               Use stdin
  --namespace NAMESPACE
                        Namespace to derive key
  --password PASSWORD   Password to derive key
  -c COUNTER, --counter COUNTER
                        Counter to derive key
  ```
  
  ## Demo
  
  #### Sign
  ```bash
  # python3 main.py --sign --password password --namespace namespace -c1 -f ~/test/test -o ~/test/test.sig --showpub
  Public Key: FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
  ```
  
  #### Verify
  ```bash
  # python3 main.py --verify -f ~/test/test -s ~/test/test.sig -p FSEMpYYohOfTIDkfSaKQro9D6xy7/yC21jZHglMDaKl1hTF6vJcADdrnByI/S6aR4EJVXKSYHv9wNyVzHlAaEg==
  Valid
  ```
