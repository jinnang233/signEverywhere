# signEverywhere

signEverywhere is a command-line tool for signing and verifying files using the SPHINCS+ signature scheme. It is an **unofficial** frontend for the PySPX library.

## Installation

1. Clone the signEverywhere repository:
```
git clone https://github.com/jinnang233/signEverywhere.git
```

2. Install the signEverywhere:
```
cd signEverywhere
pip install -r requirements.txt
python setup.py install
```

## Usage

```
sign_everywhere [command] [options]
```

### Commands

- `sign`: Sign a file with a private key.
- `verify`: Verify the signature of a file.
- `share-key`: Share public key
- `fetch-key`: Fetch a public key by key ID

### Options

- `infile`: Input file to be signed or verified.
- `--out`: Output file for the signed file (only applicable for the `sign` command).
- `--password`: Password for the private key (required for the `sign` command).
- `--namespace`: Namespace for key derivation (default: *default_namespace*).
- `--counter`: Counter for key derivation (default: *0*).
- `--showpk`: Show the public key after signing (only applicable for the `sign` command).
- `--algorithm`: Specify the SPHINCS+ algorithm to use (default: *shake_256f*).
- `--bootstrap`: Bootstrap nodes for the Kademlia network.
- `--port`: Port number for the Kademlia network (default: *8470*).
- `--run-forever`: Keep the Kademlia server running indefinitely.

### Examples

- Sign a file:

```
sign_everywhere sign infile.txt --out signed_file.txt --password mypassword
```


- Verify the signature of a file:
```
sign_everywhere verify infile.txt signature.txt public_key
```


- Run the Key server:
```
sign_everywhere  [ --bootstrap=node1,node2,node3 ] --run-forever
```

- Publish Public Key  ( Take local key server as an example )
```
sign_everywhere --port 8471 --bootstrap="127.0.0.1:8470" share-key [public_key] [yourname]
```
Result: 
```
Public Key ID: [keyid]
Fingerprint: [fingerprint]
Public Key: [public_key]
```


- Fetch Public Key  ( Take local key server as an example )
```
sign_everywhere --port 8471 --bootstrap="127.0.0.1:8470" fetch-key [keyid]
```
Result: 
```
Key ID: [keyid]
Key Bundle: {'pkey': '[public_key]', 'alg': '[alg]', 'name': '[yourname]'}
Fingerprint: [fingerprint]
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## Note

This program has been **fully rewritten** by ChatGPT, because my abilities are limited, and I **cannot** guarantee that the program is bug-free. Feel free to fork this repository and make contributions.

## License

This project is licensed under the [MIT License](LICENSE).


