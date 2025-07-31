from crypting import LatticeCrypto, load_private_key
import sys
import os

def load_file(private_file):
    try:
        if os.path.exists(private_file):
            with open(private_file, "rb") as f:
                return f.read()
        else:
            print("File does not exist, try again...")
            return None
    except:
        return None

def sign_challenge(user_id, challenge_hex, algo_variant):
    crypto = LatticeCrypto(algo_variant=algo_variant)
    try:
        private_key = load_private_key(user_id)
        if not private_key:
            print("Private key not found")
            return None
    except:
        print("No user found, try again...")
        return None
    #if load_file(private_key) != load_private_key(user_id):
    #    print("Incorrect private key, try again...")
    #    return None
    challenge = bytes.fromhex(challenge_hex)
    signature = crypto.sign(challenge, private_key)
    return signature.hex()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <user_id> <challenge_hex> <algorithm_variant>")
        sys.exit(1)
    user_id = sys.argv[1]
    #priv_key = sys.argv[2]
    challenge_hex = sys.argv[2]
    algorithm_variant = sys.argv[3]
    #if not os.path.exists(priv_key):
    #    print("File doesnt exist: [{}]".format(priv_key))
    signature = sign_challenge(user_id, challenge_hex, algorithm_variant)
    print("Gnerated Signature:\n{}".format(signature))