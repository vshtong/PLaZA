from oqs import Signature
import os
import time
import numpy as np

class LatticeCrypto:
    def __init__(self, algo_variant=None):
        """
        Initialises the LatticeCrypto class for OOP and importing in other classes
        """

        # Available Dilithium variants with increasing security and computational cost
        self.avg_sign_time = None
        self.variants = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

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
        :return: str
            Returns the dilithium variant
        """

        # Perform a test signing operation with ML-DSA-44 (fastest)
        test_sig = Signature("ML-DSA-44")
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
            return "ML-DSA-87"  # Highest security, slower
        
        elif self.avg_sign_time < 0.01:  # Medium device (e.g., standard laptop)
            return "ML-DSA-65"  # Balanced security/performance
        
        else:  # Slow device (e.g., low-end or mobile)
            return "ML-DSA-44"  # Fastest but still post-quantum secure

    def generate_keypair(self):
        """
        Generate a Dilithium key pair using selected variant.
        :return:public_key
        :return:private_key
        """

        # Record the start time of key-pair generation
        start_time = time.time()

        # Generate keypair and store public key
        pub_key = self.sig.generate_keypair()
        
        # Compute the total computation time and output result
        computation_time = (time.time() - start_time)
        print("Key-pair Computation Duration: {}".format(computation_time))
        
        # Display the length of public and private key length for comparison
        print("Generated Public Key Length: {}".format(len(pub_key)))
        print("Generated Private Key Length: {}".format(len(self.sig.secret_key)))
        return pub_key, self.sig.secret_key
    
    def sign(self, message, private_key):
        """
        Signs a challenge using the private key.
        :return:signature

        """
        # Record the start time of signature generation
        start_time = time.time()

        # signature generation
        self.sig.secret_key = private_key
        signature = self.sig.sign(message)

        # Compute the total computation time and output result
        computation_time = (time.time() - start_time)
        print("Signature Computation Duration: {}".format(computation_time))
        
        # Display the signature length for comparison
        print("Generated signature length: {}".format(len(signature)))

        return signature
    
    def verify(self, challenge, signature, public_key):
        """
        Verify a signature using the public key.
        :return: boolean
            Returns True/False if verification successful/failure

        """

        try:
            # Record the start time of signature generation
            start_time = time.time()
            
            # Verification of user signature
            verification = self.sig.verify(
                challenge, signature, public_key
            )
            # Compute the total computation time and output result
            computation_time = (time.time() - start_time)
            print("Verification Computation Duration: {}".format(computation_time))
            return verification
        except:
            return False


    def display_dilithium_specs(self, variant, sig):
        """
        For command-line logging purposes
        """

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
    :param:user_id
    :param:private_key
    
    :return:file_path
    """


    # Create a directory named "client_keys" locally, if
    # it does not already exist
    os.makedirs("client_keys", exist_ok=True)
    filepath = "client_keys/{}_sk.bin".format(user_id)

    # Save the private key within a file within this directory
    with open(filepath, "wb") as f:
        f.write(private_key)

    # Return the path onto the front-end for user visibility
    return os.path.join(os.getcwd(), filepath)

def load_private_key(user_id):
    """Load private key from file stored in user local directory.
    :param: user_id
    :return: binary private key
    """

    try:
        with open("client_keys/{}_sk.bin".format(user_id), "rb") as f:
            return f.read()
    except:
        return None