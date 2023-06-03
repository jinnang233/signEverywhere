import sys
import json
import base64
import binascii
import re
import argparse

from pyspx import SPHApp
from gettext import gettext as _

def derivePK(args, app):
    if args.password is not None:
        pk = app.derivePK(args.password)
    elif args.namespace is not None:
        pk = app.derivePK(args.namespace)
    elif args.seed is not None:
        pk = app.derivePKfromseed(args.seed)
    elif args.counter is not None:
        pk = app.derivePKfromcounter(args.counter)
    else:
        pk = app.derivePK()
    return pk

def sign_func(args, app):
    pk = derivePK(args, app)
    file = args.infile
    sig = app.sign_io(file)
    if args.out is None:
        args.out = sys.stdout
    if args.out.mode == "w":
        args.out.write(sig.decode())
    else:
        args.out.write(sig)

def verify_func(args, app):
    file = args.infile
    key_validation = True
    destpk = None
    try:
        destpk = binascii.unhexlify(args.pk)
    except binascii.Error:
        key_validation = False
    if not SPHApp.PK_pretest(destpk):
        key_validation = False
    if destpk is None:
        key_validation = False
    if not key_validation:
        print(_("Invalid PK"))
        sys.exit()
    if file is None:
        return
    valid = app.verify_io(file, args.sig, destpk)
    valid = _("Valid") if valid else _("Invalid")
    print(valid)

def print_keyresult(fingerprint, pkey_id):
    process_fingerprint = lambda fingerprint: "\t".join(re.findall(".{4}", fingerprint))
    fingerprint_b32 = base64.b32encode(binascii.unhexlify(fingerprint)).decode()
    fingerprint_b32 = process_fingerprint(fingerprint_b32)
    fingerprint_b64 = base64.b64encode(binascii.unhexlify(fingerprint)).decode()
    fingerprint_b64 = process_fingerprint(fingerprint_b64)
    fingerprint = process_fingerprint(fingerprint)
    print("[" + _("ID") + ": " + pkey_id + "]")
    print(_("Fingerprint") + ":" + fingerprint)
    print(_("Fingerprint") + "(B32):" + fingerprint_b32)
    print(_("Fingerprint") + "(B64):" + fingerprint_b64)

def default_func(args, app):
    pk = derivePK(args, app)
    if args.share:
        key = app.make_key_bundle(pk, args.alg, input(_("Enter your name here:")))
        pkey_id, fingerprint = app.store_pkey(key)
        print_keyresult(fingerprint, pkey_id)
    if args.search is not None:
        key, fingerprint = app.get_pkey(args.search)
        if key is not None:
            if args.search.upper() == app.get_pkey_id(key):
                print_keyresult(fingerprint, args.search.upper())
                for k in key.keys():
                    print(_(k) + ":\t" + key[k])
            else:
                print(_("Fake key"))
        else:
            print("Public key didn't exist.")

def main():
    app = SPHApp()
    parser = argparse.ArgumentParser()
    parser.description = _("sign or verify file with SPHINCS+. An unofficial frontend of PySPX library.")
    parser.set_defaults(func=default_func)

    subparsers = parser.add_subparsers(dest="subparser_name")

    sign_parser = subparsers.add_parser("sign", help=_("sign infile with private key"))
    sign_parser.set_defaults(func=sign_func)
    sign_parser.add_argument("infile", metavar="infile", help=_("input file to be signed"), type=argparse.FileType("rb"), default=sys.stdin)
    sign_parser.add_argument("-o", "--out", metavar="output_file", help=_("output file, default stdout"), dest="out", type=argparse.FileType("wb"))

    verify_parser = subparsers.add_parser("verify", help=_("verify signature of infile"))
    verify_parser.set_defaults(func=verify_func)
    verify_parser.add_argument("infile", metavar="infile", help=_("input file to be verified or stdin"), type=argparse.FileType("rb"), default=sys.stdin)
    verify_parser.add_argument("sig", metavar="signature_file", help=_("signature file"), type=argparse.FileType("rb"))
    verify_parser.add_argument("pk", metavar="public_key_string", help=_("public key"), type=str)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args, app)

if __name__ == "__main__":
    main()
