from sphapp import SPHApp
import getpass
import argparse
import os,sys
import base64

password_environ_name="SPassword"

def askPass(password,namespace,counter):
    if not password:
        password = getpass.getpass()
    if not namespace:
        namespace = input("Namespace:")
    if not counter:
        counter = int(input("Counter:"))
    return password,namespace,counter



#app = SPHApp()
#pk = app.derive(password,namespace,counter)
#del password,namespace,counter

if __name__=="__main__":

    parser = argparse.ArgumentParser()
    parser.description="Sign and verify file or message with SPHINCS"
    parser.add_argument("-f","--file",help="File to sign or verify", dest="filename",type=str)
    parser.add_argument("-s","--signature",help="Signature file",dest="sig",type=str)
    parser.add_argument("-o","--output",help="Output file",dest="out",type=str)
    parser.add_argument("-p","--pubkey",help="Public key",dest="pk",type=str)
    parser.add_argument("--showpub",help="Show public key",action="store_true")
    parser.add_argument("--sign",help="Sign",action="store_true")
    parser.add_argument("--verify",help="Verify",action="store_true")
    parser.add_argument("--stdin",help="Use stdin",action="store_true")
    parser.add_argument("--namespace",help="Namespace to derive key",dest="namespace")
    parser.add_argument("--password",help="Password to derive key",dest="password")
    parser.add_argument("-c","--counter",help="Counter to derive key",dest="counter",type=int)

    args = parser.parse_args()
    password, namespace, counter = None,None,None
    if password_environ_name in os.environ:
        password = os.environ.get(password_environ_name)
    if args.password != None:
        password = args.password
    if args.namespace != None:
        namespace = args.namespace
    if args.counter != None:
        counter = args.counter

    sign_opt = args.sign
    verify_opt = args.verify
    app = SPHApp()
    if sign_opt:
        password, namespace, counter = askPass(password,namespace,counter)
        pk = app.derive(password, namespace, counter)
        del password,namespace,counter
    if args.showpub:
        print("Public Key: %s" % (base64.b64encode(pk).decode()))

    if sign_opt and verify_opt:
        print("conflict: you can't use sign flag and verify flag at the same time")
        exit()
    if sign_opt and not args.out:
        print("You must use output parameter")
        exit()
    if verify_opt and ((not args.sig) or (not args.pk)):
        print("You must use signature and pk parameter")
        exit()
    if args.stdin:
        content = "".join(sys.stdin.readlines()).encode("utf-8")
    else:
        if not args.filename:
            print("No filename!")
            exit()
        if not SPHApp.isValid(args.filename):
            print("No such a file")
            exit()
        filename = args.filename
    if sign_opt:
        sig = app.sign(content) if args.stdin else app.sign_file(filename)
        with open(args.out,"wb") as f:
            f.write(sig)
    elif verify_opt:
        destpk = base64.b64decode(args.pk)
        if SPHApp.isValid(args.sig):
            with open(args.sig,"rb") as f:
                sig = f.read()
            valid = app.verify(content,sig,destpk) if args.stdin else app.verify_file(filename,sig,destpk)
            valid = "Valid" if valid else "Invalid"
            print(valid)
        else:
            print("No such a file")
    app.clear()
