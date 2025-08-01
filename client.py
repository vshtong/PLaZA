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
    """
    Client-side signature generation using the random challenge 
    and user's fetched private key.

    :param: user_id
    :param:challenge_hex
    :param:algo_variant
    :return: signature
        Returns signature in hexadecimal format
    """

    # Create a new instance object to process the challange
    crypto = LatticeCrypto(algo_variant=algo_variant)
    try:
        # Load private key
        private_key = load_private_key(user_id)

        # Error handling
        if not private_key:
            print("Private key not found")
            return None
    except:
        print("No user found, try again...")
        return None

    # Converts from hexadecimal into bytes
    challenge = bytes.fromhex(challenge_hex)

    # Generates signature from challenge and private key byte objects
    signature = crypto.sign(challenge, private_key)

    # Returns signature back in hexadecimal format
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