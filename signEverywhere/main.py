import argparse
import base64
import asyncio
from signEverywhere.sphapp import SPHApp

def default_func(args, app):
    pk = derive(args, app)
    if args.showpk:
        print("Public Key:", base64.b64encode(pk).decode())
def sign_func(args, app):
    infile = args.infile
    outfile = args.out
    password = args.password

    # Derive the public key
    pk = derive(args, app)

    # Sign the data
    signature = app.sign_file(infile.name)

    # Write the signature to the output file or stdout
    if outfile:
        outfile.write(signature)
    else:
        print("Signature:", signature)

    if args.showpk:
        print("Public Key:", base64.b64encode(pk).decode())
def verify_func(args, app):
    infile = args.infile
    sigfile = args.sig
    pk = args.pk

    # Read the input file and signature
    signature = sigfile.read()

    # Verify the signature using the public key
    result = app.verify_file(infile.name,signature,base64.b64decode(pk))
    # Print the verification result
    if result:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

def main():
    app = SPHApp()
    alg_list = app.alglist()
    default_alg = app.get_default_alg()
    
    parser = argparse.ArgumentParser()
    alg_choices="|".join(alg_list)
    parser.description = "sign or verify file with SPHINCS+"
    parser.set_defaults(func=default_func)

    subparsers = parser.add_subparsers(dest="subparser_name")

    sign_parser = subparsers.add_parser("sign", help="sign infile with private key")
    sign_parser.set_defaults(func=sign_func)
    sign_parser.add_argument("infile", metavar="infile", help="input file to be signed", type=argparse.FileType('rb'))
    sign_parser.add_argument("-o", "--out", metavar="output_file", help="output file, default stdout", dest="out", type=argparse.FileType('wb'))
    sign_parser.add_argument("--password", metavar="password", help="password for private key")
    sign_parser.add_argument("--showpk", action="store_true", help="display public key")
    sign_parser.add_argument("--namespace", metavar="namespace", help=("namespace for key derivation"), type=str, default="default_namespace")
    sign_parser.add_argument("--counter", metavar="counter", help=("counter for key derivation"), type=int, default=0)
    verify_parser = subparsers.add_parser("verify", help="verify signature of infile")
    verify_parser.set_defaults(func=verify_func)
    verify_parser.add_argument("infile", metavar="infile", help="input file to be signed", type=argparse.FileType('rb'))
    verify_parser.add_argument("sig", metavar="signature_file", help="signature file",type=argparse.FileType('rb'))
    verify_parser.add_argument("pk", metavar="public_key_string", help="public key")
    parser.add_argument(
        "--algorithm",
        metavar="algorithm",
        help=f"choose algorithm: {alg_choices}, default: {default_alg}",
        default=default_alg,
        choices=alg_list
    )
    # 添加bootstrap参数
    parser.add_argument("--bootstrap", metavar="bootstrap_nodes", help=("bootstrap nodes"), nargs="+", default=[])

    # 添加port参数
    parser.add_argument("--port", metavar="port", help=("port number"), type=int, default=8470)

    # 添加run-forever参数
    parser.add_argument("--run-forever", help=("run the server forever"), action="store_true")
    # 添加share-key子命令解析器
    share_key_parser = subparsers.add_parser("share-key", help=("share public key"))
    share_key_parser.set_defaults(func=share_key_func)
    share_key_parser.add_argument("pk", metavar="share_public_key_string", help="public key")
    share_key_parser.add_argument("name", metavar="share_name_string", help="name or email")
    fetch_key_parser = subparsers.add_parser("fetch-key", help="Fetch a public key by key ID")
    fetch_key_parser.set_defaults(func=fetch_key_func)
    fetch_key_parser.add_argument("key_id", metavar="key_id", help="key ID to fetch")
    
    args = parser.parse_args()
    # 设置bootstrap节点
    bootstrap_nodes = args.bootstrap
    bootstrap_nodes = [tuple(i.split(":")) for i in bootstrap_nodes]
    bootstrap_nodes = [(i[0],int(i[1])) for i in bootstrap_nodes]
    # 设置端口号
    port = args.port

    # 设置算法
    if args.algorithm != default_alg:
        app.change_alg(args.algorithm)

    if args.run_forever:
        app.run(bootstrap_nodes,runForever=True,port=port)
    else:
        app.run(bootstrap_nodes,port=port)
    if hasattr(args, "func"):
        args.func(args, app)
    
def fetch_key_func(args, app):
    key_id = args.key_id
    key_bundle, fingerprint = app.get_pkey(key_id)
    print(f"Key ID: {key_id}")
    print(f"Key Bundle: {key_bundle}")
    print(f"Fingerprint: {fingerprint}")
def share_key_func(args, app):
    if not args.pk:
        print("No public key available. Please derive or load a key pair.")
        return
    if not args.name:
        print("no name available. ")
        return
    #loop = asyncio.get_event_loop()
    #loop.run_until_complete(app.server_run(args.bootstrap, args.port))

    pkey_id, fingerprint = app.store_pkey(app.make_key_bundle(base64.b64decode(args.pk), args.algorithm, args.name))

    print(("Public Key ID: {}").format(pkey_id))
    print(("Fingerprint: {}").format(fingerprint))
    print(("Public Key: {}").format(args.pk))
def derive(args, app):
    password, namespace, counter = args.password, args.namespace, args.counter
    pk = app.derive(password, namespace, counter, return_seed=False)
    return pk

if __name__ == "__main__":
    main()

