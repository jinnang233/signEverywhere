from sphapp import SPHApp
import getpass
import argparse
import os,sys
import base64
import binascii

password_environ_name="SPassword"
namespace_environ_name="SNamespace"
counter_environ_name="SCounter"

app = SPHApp()
encoding_dict={"base64":base64.b64encode,"base32":base64.b32encode,"hex":binascii.hexlify}
decoding_dict = {"base64":base64.b64decode,"base32":base64.b32decode,"hex":binascii.unhexlify}

# Ask password
def askPass(password,namespace,counter):
    if not password:
        password = getpass.getpass()
    if not namespace:
        namespace = input("Namespace:")
    if not counter:
        counter = int(input("Counter:"))
    return password,namespace,counter

def argPass(args):
    password, namespace, counter = None,None,None
    if password_environ_name in os.environ:
        password = os.environ.get(password_environ_name)
    if namespace_environ_name in os.environ:
        namespace = os.environ.get(namespace_environ_name)
    if counter_environ_name in os.environ:
        counter = int(os.environ.get(counter_environ_name))
    if args.password != None:
        password = args.password
    if args.namespace != None:
        namespace = args.namespace
    if args.counter != None:
        counter = args.counter
    return password,namespace,counter

def derivePK(args,app):
    if args.subparser_name != "verify":
        password,namespace,counter = argPass(args)
        password, namespace, counter = askPass(password,namespace,counter)
        pk = app.derive(password, namespace, counter)
        del password,namespace,counter
        output_pk = encoding_dict[args.encoding](pk).decode()
        if args.showpub:
            print("Public Key: %s" % output_pk)
        if args.qrcode:
            try:
                qrcode = __import__("qrcode")
                qrcode.make(output_pk).show()
            except ImportError:
                print("No qrcode library. Please run: pip install qrcode .")
        return pk

def sign_func(args):
    pk = derivePK(args,app)
    file = args.infile
    sig = app.sign_io(file)
    with args.out as f:
        if args.out.mode=="w":
            f.write(base64.b64encode(sig).decode())
        else:
            f.write(sig)

def verify_func(args):
    file = args.infile
    destpk = decoding_dict[args.encoding](args.pk)
    if not SPHApp.PK_pretest(destpk):
        print("Invalid PK")
        sys.exit()
    valid = app.verify_io(file,args.sig,destpk)
    valid = "Valid" if valid else "Invalid"
    print(valid)
def default_func(args):
    pk = derivePK(args,app)
if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="signEverywhere")
    parser.description="Sign and verify file or message with SPHINCS"
    parser.set_defaults(func=default_func)

    subparsers = parser.add_subparsers(dest="subparser_name")

    sign_parser = subparsers.add_parser("sign",help="Sign")
    verifier_parser = subparsers.add_parser("verify",help="Verify")

    sign_parser.set_defaults(func=sign_func)
    verifier_parser.set_defaults(func=verify_func)

    sign_parser.add_argument("-f","--file",metavar="filename",help="File to sign or verify", dest="infile",nargs="?",type=argparse.FileType("rb"),default=sys.stdin,required=True)
    sign_parser.add_argument("-o","--output",metavar="output_file",help="Output file",dest="out",nargs="?",type=argparse.FileType("wb",0),default=sys.stdout,required=True)

    verifier_parser.add_argument("-f","--file",metavar="filename",help="File to sign or verify", dest="infile",nargs="?",type=argparse.FileType("rb"),default=sys.stdin,required=True)
    verifier_parser.add_argument("-s","--signature",metavar="signature_file",help="Signature file",dest="sig",type=argparse.FileType("rb"),required=True)
    verifier_parser.add_argument("-p","--pubkey",metavar="public_key_string",help="Public key",dest="pk",type=str,required=True)

    key_group = parser.add_argument_group("Key group")
    key_group.add_argument("--encoding",help="Choose encoding of public key",choices=["base64","hex","base32"],default="base64",dest="encoding")
    key_group.add_argument("--showpub",help="Show public key",action="store_true")
    key_group.add_argument("--qr","--qrcode",help="Output qrcode",dest="qrcode",action="store_true")
    key_group.add_argument("--password",help="Password to derive key",dest="password")
    key_group.add_argument("--namespace",help="Namespace to derive key",dest="namespace")
    key_group.add_argument("-c","--counter",help="Counter to derive key",dest="counter",type=int)
    key_group.add_argument("-a","--alg","--algorithm",help="Algorithm of sphincs [Default: shake_256f]",choices=SPHApp.alglist(),dest="alg",type=str,default="shake_256f")
    args = parser.parse_args()

    alg_change_result = SPHApp.change_alg(args.alg.strip())
    args.func(args)    

