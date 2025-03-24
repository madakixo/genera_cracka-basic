import string
import random
import time

# Original password generation function
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True, seed=None):
    """Generate a random password based on user specifications with optional seed."""
    if seed is not None:
        random.seed(seed)  # Set the seed for reproducibility
    
    # Base character set
    characters = string.ascii_lowercase
    
    # Additional character sets
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ensure minimum length
    if length < 8:
        length = 8
    
    # Generate password
    password = []
    if include_uppercase:
        password.append(random.choice(string.ascii_uppercase))
    if include_numbers:
        password.append(random.choice(string.digits))
    if include_symbols:
        password.append(random.choice(string.punctuation + "!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    # Fill remaining length
    remaining_length = length - len(password)
    password.extend(random.choice(characters) for _ in range(remaining_length))
    
    # Shuffle the password
    random.shuffle(password)
    return ''.join(password)

# Cracking function: Brute-force seeds in a time range
def crack_password(target_password, length, include_uppercase, include_numbers, include_symbols, time_range_seconds=3600):
    """Attempt to crack a password by brute-forcing seeds in a time range."""
    current_time = int(time.time())  # Current Unix timestamp
    start_time = current_time - time_range_seconds  # Start of time range (e.g., last hour)
    
    print(f"Attempting to crack password in {time_range_seconds} second range...")
    print(f"Searching seeds from {start_time} to {current_time}...")
    
    for seed in range(start_time, current_time + 1):
        candidate_password = generate_password(
            length=length,
            include_uppercase=include_uppercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols,
            seed=seed
        )
        if candidate_password == target_password:
            print(f"\nSuccess! Password cracked: {candidate_password}")
            print(f"Seed used: {seed} (Timestamp: {time.ctime(seed)})")
            return True
        if seed % 1000 == 0:  # Progress update every 1000 attempts
            print(f"Progress: Tried seed {seed}...")
    
    print("\nFailed to crack password within the given time range.")
    return False

# Input validation functions (unchanged)
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

if __name__ == "__main__":
    print("Password Generator and Cracker")
    print("==============================")
    
    # Step 1: Generate a password to crack (for demonstration)
    print("\nGenerating a password to crack...")
    length = get_valid_length()
    include_uppercase = get_valid_input("Include uppercase letters? (yes/no, default yes): ", True)
    include_numbers = get_valid_input("Include numbers? (yes/no, default yes): ", True)
    include_symbols = get_valid_input("Include symbols? (yes/no, default yes): ", True)
    
    # Generate the target password
    target_password = generate_password(length, include_uppercase, include_numbers, include_symbols)
    print("\nTarget password generated:", target_password)
    
    # Step 2: Attempt to crack it
    print("\nNow attempting to crack the password...")
    time_range = 3600  # Default to 1 hour (3600 seconds)
    try:
        custom_range = int(input("Enter time range in seconds to search (default 3600): ").strip() or 3600)
        time_range = max(custom_range, 1)  # Ensure positive range
    except ValueError:
        print("Invalid input, using default 3600 seconds.")
    
    # Crack the password
    crack_password(target_password, length, include_uppercase, include_numbers, include_symbols, time_range)
    
    # Optional: Strength hints
    print("\nPassword Strength Tips:")
    if length < 12:
        print("- Consider using a longer password (12+ characters) for better security")
    if not (include_uppercase and include_numbers and include_symbols):
        print("- Using uppercase, numbers, AND symbols increases password strength")
