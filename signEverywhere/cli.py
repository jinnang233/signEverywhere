import argparse
from main import main

def parse_args():
    parser = argparse.ArgumentParser()
    parser.description = "CLI for signing and verifying files with SPHINCS+"
    parser.set_defaults(func=main)
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func()

if __name__ == "__main__":
    parse_args()
