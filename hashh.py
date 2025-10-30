import hashlib

# 1. Enter the new password you want to use for 'alice'
new_password = "password123"

# 2. This will hash it using the same method as your auth service
hashed_password = hashlib.sha256(new_password.encode()).hexdigest()

# 3. The script will print the hash you need
print(f"The SHA-256 hash for '{new_password}' is:")
print(hashed_password)