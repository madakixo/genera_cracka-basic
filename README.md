# genera_cracka-basic

How This Works
Password Generation:
The generate_password function is modified to accept an optional seed parameter, allowing control over the random number generator for cracking purposes.

It generates a password using the same logic as your original script, ensuring at least one character from each selected category and shuffling the result.

Cracking Mechanism:
The crack_password function brute-forces possible seeds within a specified time range (default: 1 hour, or 3,600 seconds).

It starts from the current time minus the time range (start_time) and iterates up to the current time (current_time), setting each seed with random.seed(seed) and generating a candidate password.

If a candidate matches the target password, it reports success with the seed and timestamp; otherwise, it continues until the range is exhausted.

Main Execution:
The script first generates a target password using user-specified parameters.

It then attempts to crack that password by searching seeds in the specified time range.

Progress updates are printed every 1,000 attempts to keep the user informed.

Input Handling:
Reuses your get_valid_input and get_valid_length functions for consistency.

Adds a prompt for the time range to search, with a default of 3,600 seconds (1 hour).

