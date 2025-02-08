import hashlib
import time
import string
import itertools

# Dictionary of common weak passwords
weak_passwords = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

# Function to calculate password entropy
def calculate_entropy(password):
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    
    entropy = len(password) * (charset_size.bit_length())
    return entropy

# Function to estimate cracking time
def estimate_crack_time(password):
    entropy = calculate_entropy(password)
    attempts_per_second = 1e9  # Approximate for a powerful modern system
    seconds_to_crack = 2 ** entropy / attempts_per_second
    return seconds_to_crack

# Function to check password strength
def password_strength(password):
    if password in weak_passwords:
        return "Very Weak - Commonly used password"
    
    entropy = calculate_entropy(password)
    seconds_to_crack = estimate_crack_time(password)
    
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 90:
        return "Strong"
    else:
        return "Very Strong"

# Testing
def main():
    password = input("Enter a password to check: ")
    strength = password_strength(password)
    time_to_crack = estimate_crack_time(password)
    print(f"Password Strength: {strength}")
    print(f"Estimated Crack Time: {time_to_crack:.2f} seconds")

if __name__ == "__main__":
    main()
