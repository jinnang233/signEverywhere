from signEverywhere.sphapp import SPHApp
import getpass
import argparse
import os,sys
import base64
import binascii
import gettext
import locale
import json
import re
import pkg_resources
import binascii
# Multi language support
loc = locale.getlocale()
get_lang = lambda lc, localedir:gettext.translation(lc,localedir=localedir,languages=[lc.replace("_","-")],fallback=False)
locale_path = pkg_resources.resource_filename("signEverywhere","locales")
lang = get_lang(loc[0],locale_path)
lang.install()
_ = lang.gettext

# Environment vars
password_environ_name="SPassword"
namespace_environ_name="SNamespace"
counter_environ_name="SCounter"

# Initializing
app = SPHApp()
encoding_dict={"base64":base64.b64encode,"base32":base64.b32encode,"hex":binascii.hexlify}
decoding_dict = {"base64":base64.b64decode,"base32":base64.b32decode,"hex":binascii.unhexlify}

# Ask password
def askPass(password,namespace,counter):
    if not password:
        password = getpass.getpass(_("Password:"))
    if not namespace:
        namespace = input(_("Namespace:"))
    if not counter:
        counter = int(input(_("Counter:")))
    return password,namespace,counter

# Get password,namespace, counter from environment var
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

# Get Public key from seed
def seedPass(args,app):
    if args.seed != None:
        seed = None
        try:
            seed = decoding_dict[args.encoding](args.seed)
        except binascii.Error:
            return None
        pk = app.derive_seed(seed)
        return pk
    return None

# Derive public key
# Order: Seed > environment vars > ask password
def derivePK(args,app):
    if args.subparser_name != "verify":
        password,namespace,counter=None,None,None
        pk = seedPass(args, app)
        if pk is None:
            password, namespace, counter = argPass(args)
            password, namespace, counter = askPass(password,namespace,counter)
            pk = app.derive(password, namespace, counter)
        
        output_pk = encoding_dict[args.encoding](pk).decode()
        if args.showpub:
            print(_("Public Key:") +  "%s" % output_pk)
        if args.showseed:
            seed = app.derive(password,namespace, counter,return_seed=True)
            output_seed = encoding_dict[args.encoding](seed).decode()
            print(_("Keypair seed: ") + "%s" % output_seed)
        del password,namespace,counter
        if args.qrcode:
            try:
                qrcode = __import__("qrcode")
                qrcode.make(output_pk).show()
            except ImportError:
                print(_("No qrcode library. Please run: pip install Image qrcode ."))
        return pk


def sign_func(args):
    pk = derivePK(args,app)
    file = args.infile
    sig = app.sign_io(file)
    if args.out is None:
        args.out=sys.stdout
    if args.out.mode=="w":
        args.out.write(encoding_dict[args.encoding](sig).decode())
    else:
        args.out.write(sig)

def verify_func(args):
    file = args.infile
    key_validation = True
    destpk = None
    try:
        destpk = decoding_dict[args.encoding](args.pk)
    except binascii.Error:
        key_validation = False
    if not SPHApp.PK_pretest(destpk):
        key_validation = False
    if destpk == None:
        key_validation = False
    if not key_validation:
        print(_("Invalid PK"))
        sys.exit()
    if file is None:
        return
    
    valid = app.verify_io(file,args.sig,destpk)
    valid = _("Valid") if valid else _("Invalid")
    print(valid)
def print_keyresult(fingerprint, pkey_id):
    process_fingerprint = lambda fingerprint: "\t".join(re.findall(".{4}",fingerprint)) 
    fingerprint_b32 = base64.b32encode(binascii.unhexlify(fingerprint)).decode()
    fingerprint_b32 = process_fingerprint(fingerprint_b32)
    fingerprint_b64 = base64.b64encode(binascii.unhexlify(fingerprint)).decode()
    fingerprint_b64 = process_fingerprint(fingerprint_b64)
    fingerprint = process_fingerprint(fingerprint)
    print("["+_("ID") + ": " + pkey_id + "]")
    print(_("Fingerprint") + ":" + fingerprint)
    print(_("Fingerprint") + "(B32):" + fingerprint_b32)
    print(_("Fingerprint") + "(B64):" + fingerprint_b64)
def default_func(args):
    pk = derivePK(args,app)
    if args.share==True:
        key = app.make_key_bundle(pk,args.alg,input(_("Enter your name here:")))
        pkey_id, fingerprint = app.store_pkey(key)
        print_keyresult(fingerprint,pkey_id) 
    if args.search != None:
        key,fingerprint = app.get_pkey(args.search)
        if key != None:
            if args.search.upper() == app.get_pkey_id(key):
                print_keyresult(fingerprint,args.search.upper())
                for k in key.keys():
                    print(_(k)+":\t"+key[k])
            else:
                print(_("Fake key"))
        else:
            print("Public key didn't exist.")

            

def main():
    parser = argparse.ArgumentParser()
    parser.description=_("sign or verify file with SPHINCS+. An unofficial frontend of PySPX library.")
    parser.set_defaults(func=default_func)

    subparsers = parser.add_subparsers(dest="subparser_name")

    sign_parser = subparsers.add_parser("sign",help=_("Sign"))
    verifier_parser = subparsers.add_parser("verify",help=_("Verify"))

    sign_parser.set_defaults(func=sign_func)
    verifier_parser.set_defaults(func=verify_func)

    sign_parser.add_argument("-f","--file",metavar="filename",help=_("file to be signed or verified"), dest="infile",nargs="?",type=argparse.FileType("rb"),default=sys.stdin,required=True)
    sign_parser.add_argument("-o","--output",metavar="output_file",help=_("output file"),dest="out",nargs="?",type=argparse.FileType("wb",0),default=sys.stdout,required=False)

    verifier_parser.add_argument("-f","--file",metavar="filename",help=_("file to be signed or verified"), dest="infile",nargs="?",type=argparse.FileType("rb"),default=sys.stdin,required=True)
    verifier_parser.add_argument("-s","--signature",metavar="signature_file",help=_("signature file"),dest="sig",type=argparse.FileType("rb"),required=True)
    verifier_parser.add_argument("-p","--pubkey",metavar="public_key_string",help=_("public key"),dest="pk",type=str,required=True)
    key_group = parser.add_argument_group("Key group")
    key_group.add_argument("--encoding",help=_("encoding of public key"),choices=["base64","hex","base32"],default="base64",dest="encoding")
    key_group.add_argument("--showpub",help=_("show public key"),action="store_true")
    key_group.add_argument("--nodelist",help=_("node list file"),dest="nodelist",nargs="?",type=argparse.FileType("rb"))
    key_group.add_argument("--share",help=_("share my public key"), dest="share",action="store_true")
    key_group.add_argument("--search",help=_("search public key by id"),dest="search",type=str)
    key_group.add_argument("--runasnode","--asnode",help=_("Run as node"), dest="runasnode",action="store_true")
    key_group.add_argument("--port","--node-port",help=_("Node port"),dest="port",type=int,default=8470)
    key_group.add_argument("--showseed",help=_("show seed of keypair"),action="store_true")
    key_group.add_argument("--qr","--qrcode",help=_("show qrcode"),dest="qrcode",action="store_true")
    key_group.add_argument("--password",help=_("password to derive key"),dest="password")
    key_group.add_argument("--namespace",help=_("namespace to derive key"),dest="namespace")
    key_group.add_argument("--seed",help=_("seed to derive key"),dest="seed")
    key_group.add_argument("-c","--counter",help=_("counter to derive key"),dest="counter",type=int)
    key_group.add_argument("-a","--alg","--algorithm",help=_("algorithm of sphincs [Default: {}]").format(SPHApp.get_default_alg()),choices=SPHApp.alglist(),dest="alg",type=str,default=SPHApp.get_default_alg())
    args = parser.parse_args()
    nodelist = []
    if args.nodelist != None:
        with args.nodelist as f:
            nodelist = json.load(f)
        node_list = []
        for node in nodelist:
            dhost, dport = node.split(":")
            node_list.append((dhost,int(dport)))
        app.run(node_list,args.runasnode,port=args.port)
    
    alg_change_result = SPHApp.change_alg(args.alg.strip())
    args.func(args)    

