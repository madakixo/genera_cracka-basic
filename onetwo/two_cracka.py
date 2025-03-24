import string
import random
import time
import hashlib
from multiprocessing import Pool, cpu_count
from functools import partial

# Password generation function with optional seed
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True, seed=None):
    """Generate a random password based on user specifications with optional seed."""
    if seed is not None:
        random.seed(seed)
    
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
        password.append(random.choice(string.ascii_uppercase))
    if include_numbers:
        password.append(random.choice(string.digits))
    if include_symbols:
        password.append(random.choice(string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    remaining_length = length - len(password)
    password.extend(random.choice(characters) for _ in range(remaining_length))
    
    random.shuffle(password)
    return ''.join(password)

# Hashing function with selectable algorithm
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

# Worker function for multiprocessing
def crack_worker(seed, target_hash, length, include_uppercase, include_numbers, include_symbols, hash_algorithm):
    """Generate a password with a given seed and check if its hash matches the target."""
    candidate_password = generate_password(
        length=length,
        include_uppercase=include_uppercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols,
        seed=seed
    )
    candidate_hash = hash_password(candidate_password, hash_algorithm)
    if candidate_hash == target_hash:
        return (seed, candidate_password)
    return None

# Cracking function using multiprocessing
def crack_password(target_hash, length, include_uppercase, include_numbers, include_symbols, 
                  time_range_seconds=3600, hash_algorithm='sha256'):
    """Crack a hashed password by brute-forcing seeds in parallel."""
    current_time = int(time.time())
    start_time = current_time - time_range_seconds
    seeds = range(start_time, current_time + 1)
    total_seeds = len(seeds)
    
    print(f"Attempting to crack hashed password in {time_range_seconds} second range...")
    print(f"Searching {total_seeds} seeds from {start_time} to {current_time} using {cpu_count()} CPU cores...")
    
    # Use multiprocessing Pool
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
        results = pool.map(worker_func, seeds)
        
        # Check results for a match
        for result in results:
            if result:
                seed, cracked_password = result
                print(f"\nSuccess! Password cracked: {cracked_password}")
                print(f"Seed used: {seed} (Timestamp: {time.ctime(seed)})")
                print(f"Hashed value: {target_hash}")
                return True
    
    print("\nFailed to crack password within the given time range.")
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
    print("Password Generator and Cracker with Hashing")
    print("===========================================")
    
    # Step 1: Generate a password and its hash (for demonstration)
    print("\nGenerating a password to crack...")
    length = get_valid_length()
    include_uppercase = get_valid_input("Include uppercase letters? (yes/no, default yes): ", True)
    include_numbers = get_valid_input("Include numbers? (yes/no, default yes): ", True)
    include_symbols = get_valid_input("Include symbols? (yes/no, default yes): ", True)
    hash_algorithm = get_hash_algorithm()
    
    target_password = generate_password(length, include_uppercase, include_numbers, include_symbols)
    target_hash = hash_password(target_password, hash_algorithm)
    print("\nGenerated password (for demo):", target_password)
    print(f"Hashed password ({hash_algorithm}):", target_hash)
    
    # Step 2: Attempt to crack the hashed password
    print("\nNow attempting to crack the hashed password...")
    time_range = 3600
    try:
        custom_range = int(input("Enter time range in seconds to search (default 3600): ").strip() or 3600)
        time_range = max(custom_range, 1)
    except ValueError:
        print("Invalid input, using default 3600 seconds.")
    
    # Crack the hashed password
    crack_password(target_hash, length, include_uppercase, include_numbers, include_symbols, 
                  time_range, hash_algorithm)
    
    # Strength hints
    print("\nPassword Strength Tips:")
    if length < 12:
        print("- Consider using a longer password (12+ characters) for better security")
    if not (include_uppercase and include_numbers and include_symbols):
        print("- Using uppercase, numbers, AND symbols increases password strength")
