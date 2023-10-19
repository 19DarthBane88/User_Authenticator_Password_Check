import bcrypt
import datetime
# Initialize an empty user database.
user_db = {
    "user1": {
        "password_hash": bcrypt.hashpw(b'P@ssword1', bcrypt.gensalt()),
        "last_password_change_date": datetime.datetime(2023, 7, 1),
    },
    "user2": {
        "password_hash": bcrypt.hashpw(b'strongP@ssword123', bcrypt.gensalt()),
        "last_password_change_date": datetime.datetime(2023, 9, 1),
    },
    # Add more users here
}
# Check if the password meets complexity standards
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isalnum() for char in password):
        return False

    return True
# Check if the password is not older than 90 days
def is_password_recent(last_change_date):
    current_date = datetime.datetime.now()
    days_since_change = (current_date - last_change_date).days
    return days_since_change <= 90

def add_user(username, password):
    if username in user_db:
        return "Username already exists. Choose a different username."

    if is_valid_password(password):
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        last_change_date = datetime.datetime.now()
        user_db[username] = {"password_hash": password_hash, "last_password_change_date": last_change_date}
        return "User added successfully."
    else:
        return "Password does not meet complexity standards."

def authenticate_user(username, password):
    user_data = user_db.get(username)

    if user_data is None:
        return "User not found"

    if not is_password_recent(user_data["last_password_change_date"]):
        return "Password is older than 90 days. Please reset your password."

    stored_password_hash = user_data["password_hash"]
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
        return "Authentication successful"
    else:
        return "Incorrect password"

if __name__ == "__main__":
    while True:
        print("1. Add a user")
        print("2. Authenticate a user")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            result = add_user(username, password)
            print(result)
        elif choice == "2":
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            result = authenticate_user(username, password)
            print(result)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please select a valid option.")