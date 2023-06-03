import argparse
import base64
from signEverywhere.sphapp import SPHApp

def default_func(args, app):
    pk = derive(args, app)
    if args.showpk:
        print("Public Key:", base64.b64encode(pk).decode())
def sign_func(args, app):
    infile = args.infile
    outfile = args.out
    password = args.password

    # Read the input file
    data = infile.read()

    # Derive the public key
    pk = derive(args, app)

    # Sign the data
    signature = app.sign(data)

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
    data = infile.read()
    signature = sigfile.read()

    # Verify the signature using the public key
    result = app.verify(data, signature, base64.b64decode(pk))

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
    parser.add_argument('--namespace', help='Your namespace')
    parser.add_argument('--counter', help='Your counter', type=int)
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

    args = parser.parse_args()
    # 设置算法
    if args.algorithm != default_alg:
        app.change_alg(args.algorithm)

    if hasattr(args, "func"):
        args.func(args, app)

def derive(args, app):
    password, namespace, counter = args.password, args.namespace, args.counter
    pk = app.derive(password, namespace, counter, return_seed=False)
    return pk

if __name__ == "__main__":
    main()

