from sphapp import SPHApp
import getpass
import argparse
import os,sys
import base64
import binascii

password_environ_name="SPassword"

def askPass(password,namespace,counter):
    if not password:
        password = getpass.getpass()
    if not namespace:
        namespace = input("Namespace:")
    if not counter:
        counter = int(input("Counter:"))
    return password,namespace,counter

if __name__=="__main__":
    encoding_dict={"base64":base64.b64encode,"base32":base64.b32encode,"hex":binascii.hexlify}
    decoding_dict = {"base64":base64.b64decode,"base32":base64.b32decode,"hex":binascii.unhexlify}
    parser = argparse.ArgumentParser()
    parser.description="Sign and verify file or message with SPHINCS"
    operation_group = parser.add_mutually_exclusive_group(required=False)
    sign_parser = parser.add_subparsers("--sign",help="Sign",action="store_true")
    verifier_parser = parser.add_subparsers("--verify",help="Verify",action="store_true")

    subparsers = parser.add_subparsers()
    
    parser.add_argument("-f","--file",help="File to sign or verify", dest="infile",nargs="?",type=argparse.FileType("rb"),default=sys.stdin)
    sign_group = sign_parser.add_argument_group("Sign group")
    sign_group.add_argument("-o","--output",help="Output file",dest="out",nargs="?",type=argparse.FileType("wb",0),default=sys.stdout)

    verify_group = verifier_parser.add_argument_group("Verify group")
    verify_group.add_argument("-s","--signature",help="Signature file",dest="sig",type=argparse.FileType("rb"))

    verify_group.add_argument("-p","--pubkey",help="Public key",dest="pk",type=str)

    key_group = parser.add_argument_group("Key group")
    key_group.add_argument("--encoding",help="Choose encoding of public key",choices=["base64","hex","base32"],default="base64",dest="encoding")
    key_group.add_argument("--showpub",help="Show public key",action="store_true")
    key_group.add_argument("--qr","--qrcode",help="Output qrcode",dest="qrcode",action="store_true")
    key_group.add_argument("--password",help="Password to derive key",dest="password")
    key_group.add_argument("--namespace",help="Namespace to derive key",dest="namespace")
    key_group.add_argument("-c","--counter",help="Counter to derive key",dest="counter",type=int)
    key_group.add_argument("-a","--alg","--algorithm",help="Algorithm of sphincs [Default: shake_256f]",dest="alg",type=str,default="shake_256f")
    args = parser.parse_args()
    sign_opt = args.sign
    verify_opt = args.verify
    app = SPHApp()
    password, namespace, counter = None,None,None
    if password_environ_name in os.environ:
        password = os.environ.get(password_environ_name)
    if args.password != None:
        password = args.password
    if args.namespace != None:
        namespace = args.namespace
    if args.counter != None:
        counter = args.counter
    
    if args.alg != None:
        alg_change_result = SPHApp.change_alg(args.alg.strip())
        if not alg_change_result:
            print("Algorithm changed failed, use default algorithm: shake_256f")
            print("Valid algorithms:\n\t{}".format("\n\t".join(SPHApp.alglist())))

    if not verify_opt:
        password, namespace, counter = askPass(password,namespace,counter)
        pk = app.derive(password, namespace, counter)
        del password,namespace,counter
        output_pk = encoding_dict[args.encoding](pk).decode()
        #output_pk = (binascii.hexlify(pk) if args.hex else base64.b64encode(pk)).decode()
        if args.showpub:
            print("Public Key: %s" % output_pk)
        if args.qrcode:
            try:
                qrcode = __import__("qrcode")
                qrcode.make(output_pk).show()
            except ImportError:
                print("No qrcode library. Please run: pip install qrcode .")
    if sign_opt and not args.out:
        print("Output required")
        sys.exit()
    if verify_opt and ((not args.sig) or (not args.pk)):
        print("Public key and signature required")
        sys.exit()
    if not (sign_opt or verify_opt):
        sys.exit()
    if not args.infile or not args.out:
        print("No infile!")
        sys.exit()
    file = args.infile
    if sign_opt:
        sig = app.sign_io(file)
        with args.out as f:
            if args.out.mode=="w":
                f.write(base64.b64encode(sig).decode())
            else:
                f.write(sig)
    elif verify_opt:
        destpk = decoding_dict[args.encoding](args.pk)
        if not SPHApp.PK_pretest(destpk):
            print("Invalid PK")
            sys.exit()
        valid = app.verify_io(file,args.sig,destpk)
        valid = "Valid" if valid else "Invalid"
        print(valid)
    
    app.clear()
