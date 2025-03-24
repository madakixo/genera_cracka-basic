"""Why Use Cryptographic Random Number Generators?
random Module: Uses the Mersenne Twister PRNG, seeded by time if unspecified, making it predictable and reversible if the seed is guessed.
This was exploitable in the previous cracking approach.
secrets Module: Provides cryptographically strong randomness, sourced from the operating system’s secure random number generator
(e.g., /dev/urandom on Unix, CryptGenRandom on Windows). It’s designed for security-sensitive applications like password generation, 
with no seed-based predictability.
With secrets, cracking via seed brute-forcing is no longer feasible because there’s no seed to guess—the randomness is truly unpredictable.
"""

import string
import secrets
import time
import hashlib
from multiprocessing import Pool, cpu_count
from functools import partial

# Password generation with cryptographic randomness
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True):
    """Generate a cryptographically secure password."""
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if length < 8:
        length = 8
    
    password = []
    if include_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if include_numbers:
        password.append(secrets.choice(string.digits))
    if include_symbols:
        password.append(secrets.choice(string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    remaining_length = length - len(password)
    password.extend(secrets.choice(characters) for _ in range(remaining_length))
    
    # Shuffle using secrets (no seed, truly random)
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# Hashing function
def hash_password(password, algorithm='sha256'):
    """Hash a password using the specified algorithm."""
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm. Use 'md5', 'sha1', or 'sha256'.")

# Worker function for brute-force attempt (non-seed based)
def crack_worker(candidate_chars, target_hash, length, include_uppercase, include_numbers, include_symbols, hash_algorithm):
    """Generate a random password and check its hash (brute-force without seeds)."""
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = list(candidate_chars)  # Use provided characters as a starting point
    while len(password) < length:
        password.append(secrets.choice(characters))
    secrets.SystemRandom().shuffle(password)
    candidate_password = ''.join(password[:length])
    
    candidate_hash = hash_password(candidate_password, hash_algorithm)
    if candidate_hash == target_hash:
        return candidate_password
    return None

# Cracking function (brute-force without seeds)
def crack_password(target_hash, length, include_uppercase, include_numbers, include_symbols, 
                  attempts=100000, hash_algorithm='sha256'):
    """Attempt to crack a hashed password via brute-force (no seed possible)."""
    print(f"Attempting to crack hashed password with {attempts} brute-force attempts...")
    print(f"Using {cpu_count()} CPU cores...")
    
    # Generate initial character sets for workers
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Minimum required characters
    min_chars = []
    if include_uppercase:
        min_chars.append(secrets.choice(string.ascii_uppercase))
    if include_numbers:
        min_chars.append(secrets.choice(string.digits))
    if include_symbols:
        min_chars.append(secrets.choice(string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    # Prepare inputs for multiprocessing
    worker_inputs = [min_chars for _ in range(attempts)]
    
    with Pool(processes=cpu_count()) as pool:
        worker_func = partial(
            crack_worker,
            target_hash=target_hash,
            length=length,
            include_uppercase=include_uppercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols,
            hash_algorithm=hash_algorithm
        )
        results = pool.map(worker_func, worker_inputs)
        
        for result in results:
            if result:
                print(f"\nSuccess! Password cracked: {result}")
                print(f"Hashed value: {target_hash}")
                return True
    
    print(f"\nFailed to crack password after {attempts} attempts.")
    print("Note: With cryptographic randomness, seed-based cracking is impossible.")
    return False

# Input validation functions
def get_valid_input(prompt, default=True):
    """Get and validate yes/no input from user."""
    while True:
        response = input(prompt).lower().strip()
        if response in ['yes', 'y', '']:
            return default if response == '' else True
        elif response in ['no', 'n']:
            return False
        print("Please enter 'yes' or 'no' (or press Enter for default)")

def get_valid_length():
    """Get and validate password length input."""
    while True:
        try:
            length = input("Enter password length (minimum 8, press Enter for 12): ").strip()
            if length == "":
                return 12
            length = int(length)
            if length < 8:
                print("Hint: For better security, use at least 8 characters.")
                return 8
            return length
        except ValueError:
            print("Please enter a valid number")

def get_hash_algorithm():
    """Get and validate hash algorithm input."""
    while True:
        algo = input("Enter hash algorithm (md5, sha1, sha256, default sha256): ").strip().lower() or 'sha256'
        if algo in ['md5', 'sha1', 'sha256']:
            return algo
        print("Please enter 'md5', 'sha1', or 'sha256'")

if __name__ == "__main__":
    print("Secure Password Generator and Cracker")
    print("=====================================")
    
    # Generate a secure password
    print("\nGenerating a cryptographically secure password...")
    length = get_valid_length()
    include_uppercase = get_valid_input("Include uppercase letters? (yes/no, default yes): ", True)
    include_numbers = get_valid_input("Include numbers? (yes/no, default yes): ", True)
    include_symbols = get_valid_input("Include symbols? (yes/no, default yes): ", True)
    hash_algorithm = get_hash_algorithm()
    
    target_password = generate_password(length, include_uppercase, include_numbers, include_symbols)
    target_hash = hash_password(target_password, hash_algorithm)
    print("\nGenerated password (for demo):", target_password)
    print(f"Hashed password ({hash_algorithm}):", target_hash)
    
    # Attempt to crack (brute-force only)
    print("\nNow attempting to crack the hashed password...")
    try:
        attempts = int(input("Enter number of brute-force attempts (default 100000): ").strip() or 100000)
        attempts = max(attempts, 1)
    except ValueError:
        print("Invalid input, using default 100000 attempts.")
    
    crack_password(target_hash, length, include_uppercase, include_numbers, include_symbols, 
                  attempts, hash_algorithm)
    
    # Strength hints
    print("\nPassword Strength Tips:")
    if length < 12:
        print("- Consider using a longer password (12+ characters) for better security")
    if not (include_uppercase and include_numbers and include_symbols):
        print("- Using uppercase, numbers, AND symbols increases password strength")
    print("- This password uses cryptographic randomness, making it highly secure against seed-based attacks.")

  
