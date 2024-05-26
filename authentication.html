import hashlib
import secrets
import getpass

# Dictionary to store user credentials
credentials = {}

def generate_hash(password, salt):
    """Create a SHA-256 hash for a given password and salt."""
    return hashlib.sha256((password + salt).encode()).hexdigest()

def create_user():
    """Register a new user with a unique username and a secure password."""
    print("\n--- Register ---")
    username = input("Enter a new username: ")
    if username in credentials:
        print("This username is already taken. Please choose another.")
        return

    password = getpass.getpass("Enter a new password: ")
    if len(password) < 6:
        print("Password must be at least 6 characters long.")
        return

    salt = secrets.token_hex(16)
    hashed_password = generate_hash(password, salt)
    credentials[username] = {'salt': salt, 'hashed_password': hashed_password}
    print("Registration successful!\n")

def authenticate_user():
    """Authenticate an existing user by verifying their password."""
    print("\n--- Login ---")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    
    if username in credentials:
        stored_info = credentials[username]
        hashed_password = generate_hash(password, stored_info['salt'])
        
        if hashed_password == stored_info['hashed_password']:
            print("Login successful!")
            secure_area()
            return
    print("Incorrect username or password.\n")

def secure_area():
    """Access a secure area after successful authentication."""
    print("\n--- Secure Area ---")
    print("Welcome! You have successfully accessed the secure area.")
    print("----------------------------------\n")

def display_menu():
    """Display the main menu for user interaction."""
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        option = input("Select an option: ")
        
        if option == '1':
            create_user()
        elif option == '2':
            authenticate_user()
        elif option == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# Start the main menu
display_menu()
