from oqs import Signature
import os
import time
import numpy as np


class LatticeCrypto:
    def __init__(self, algo_variant=None):
        # Available Dilithium variants with increasing security and computational cost
        self.avg_sign_time = None
        self.variants = ["Dilithium2", "Dilithium3", "Dilithium5"]

        # Select variant based on device performance
        if algo_variant in ["", "Auto", None]:
            self.algorithm = self.algorithm_benchmark()
        else:
            if algo_variant not in self.variants: # Checks if specified Dilithium is a valid variant
                raise TypeError("Your provided Dilithium algorithm variant "
                                "[{}] does not exist in accepted Dilithium variants: {}.".format(
                                    algo_variant, self.variants
                                )
                )
            self.algorithm = algo_variant
        self.sig = Signature(self.algorithm)
        self.display_dilithium_specs(self.algorithm, self.sig)
        print("Selected Dilithium variant: {}".format(self.algorithm))
    

    def algorithm_benchmark(self):
        """
        Benchmark the device and select Dilithium variant based on computational capacity.
        """

        # Perform a test signing operation with Dilithium2 (fastest)
        test_sig = Signature("Dilithium2")
        test_message = b"test_message"
        
        # Measure signing time (average of 3 runs for reliability)
        num_runs = 3
        start_time = time.time()

        for _ in range(num_runs):
            test_pk, test_sk = test_sig.generate_keypair(), test_sig.secret_key
            test_sig.sign(test_message)
        
        self.avg_sign_time = (time.time() - start_time) / num_runs

        print("self.avg_sign_time: {}".format(self.avg_sign_time))

        # Thresholds for selecting variant (in seconds, tuned for typical devices)
        if self.avg_sign_time < 0.005:  # Fast device (e.g., high-end CPU)
            return "Dilithium5"  # Highest security, slower
        
        elif self.avg_sign_time < 0.01:  # Medium device (e.g., standard laptop)
            return "Dilithium3"  # Balanced security/performance
        
        else:  # Slow device (e.g., low-end or mobile)
            return "Dilithium2"  # Fastest but still post-quantum secure

    def generate_keypair(self):
        """
        Generate a Dilithium key pair using selected variant.
        """
        return self.sig.generate_keypair(), self.sig.secret_key
    
    def sign(self, message, private_key):
        """
        Sign a message using the private key.
        """
        self.sig.secret_key = private_key
        return self.sig.sign(message)
    
    def verify(self, message, signature, public_key):
        """
        Verify a signature using the public key.
        """

        try:
            return self.sig.verify(
                message, signature, public_key
            )
        except:
            return False


    def display_dilithium_specs(self, variant, sig):

        try:            
            # Get algorithm details
            details = sig.details
            
            # Print relevant specifications
            print("\nSpecifications for {}:".format(variant))
            print("Claimed NIST Security Level: {}".format(details['claimed_nist_level']))
            print("Public Key Size: {} bytes".format(details['length_public_key']))
            print("Private Key Size: {} bytes".format(details['length_secret_key']))
            print("Signature Size: {} bytes".format(details['length_signature']))
            
        except Exception as e:
            print("Error retrieving specs for {variant}: {e}")


def save_private_key(user_id, private_key):
    """
    Save private key to file in user local directory.
    """

    os.makedirs("client_keys", exist_ok=True)
    filepath = "client_keys/{}_sk.bin".format(user_id)
    with open(filepath, "wb") as f:
        f.write(private_key)
    return os.path.join(os.getcwd(), filepath)

def load_private_key(user_id):
    """Load private key from file stored in user local directory.
    """
    try:
        with open("client_keys/{}_sk.bin".format(user_id), "rb") as f:
            return f.read()
    except:
        return None