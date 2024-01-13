# from passlib.hash import argon2, bcrypt

import hashlib
import secrets
import argon2
import bcrypt
import os

from colorama import Fore, Style, init

init(autoreset = True)

def generate_argon2_hash(password):
    try:
        ph = argon2.PasswordHasher()
        hash_value = ph.hash(password)
        return hash_value

    except argon2.exceptions.Argon2Error as e:
        print(Fore.RED + f"Error generating Argon2 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating Argon2 hash: {e}" + Style.RESET_ALL)
        return None

def generate_bcrypt_hash(password):
    try:
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating Bcrypt hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating Bcrypt hash: {e}" + Style.RESET_ALL)
        return None

def generate_scrypt_hash(ascii_str):
    try:
        salt = secrets.token_bytes(16)
        scrypt_result = hashlib.scrypt(ascii_str.encode(), salt=salt, n=2**14, r=8, p=1)
        return scrypt_result.hex()

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating Scrypt hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating Scrypt hash: {e}" + Style.RESET_ALL)
        return None

def generate_md5_hash(password):
    try:
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        return md5_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating MD5 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating MD5 hash: {e}" + Style.RESET_ALL)
        return None

def generate_sha256_hash(password):
    try:
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        return sha256_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating SHA-256 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating SHA-256 hash: {e}" + Style.RESET_ALL)
        return None

def generate_sha512_hash(password):
    try:
        sha512_hash = hashlib.sha512(password.encode()).hexdigest()
        return sha512_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating SHA-512 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating SHA-512 hash: {e}" + Style.RESET_ALL)
        return None

def generate_blake2b_hash(password):
    try:
        blake2b_hash = hashlib.blake2b(password.encode()).hexdigest()
        return blake2b_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating Blake2b hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating Blake2b hash: {e}" + Style.RESET_ALL)
        return None

def generate_pbkdf2_hmac_hash(password):
    try:
        salt = secrets.token_bytes(16)
        pbkdf2_hmac_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return pbkdf2_hmac_hash.hex()

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating PBKDF2-HMAC hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating PBKDF2-HMAC hash: {e}" + Style.RESET_ALL)
        return None

def generate_shake128_hash(password):
    try:
        shake = hashlib.shake_128()
        shake.update(password.encode())
        shake128_hash = shake.hexdigest(32)
        return shake128_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating SHAKE-128 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating SHAKE-128 hash: {e}" + Style.RESET_ALL)
        return None

def generate_shake256_hash(password):
    try:
        shake = hashlib.shake_256()
        shake.update(password.encode())
        shake256_hash = shake.hexdigest(64)
        return shake256_hash

    except (ValueError, TypeError) as e:
        print(Fore.RED + f"Error generating SHAKE-256 hash: {e}" + Style.RESET_ALL)
        return None

    except Exception as e:
        print(Fore.RED + f"Unexpected error generating SHAKE-256 hash: {e}" + Style.RESET_ALL)
        return None

def clear_screen():
    os.system('cls||clear') # Execute a system command to clear the screen (works on both Windows and Unix-like systems)

def display_menu():
    clear_screen()

    menu = (
        Fore.LIGHTBLACK_EX + "Choose a hashing algorithm:\n" +
        Fore.RED + "   0. Exit\n" +
        Fore.CYAN + "   1. Argon2\n" +
        Fore.LIGHTMAGENTA_EX + "   2. BCrypt\n" +
        Fore.LIGHTYELLOW_EX + "   3. SCrypt\n" +
        Fore.YELLOW + "   4. MD5\n" +
        Fore.GREEN + "   5. SHA-256\n" +
        Fore.LIGHTRED_EX + "   6. SHA-512\n" +
        Fore.CYAN + "   7. Blake2b\n" +
        Fore.LIGHTMAGENTA_EX + "   8. PBKDF2-HMAC\n" +
        Fore.LIGHTYELLOW_EX + "   9. SHAKE-128\n" +
        Fore.YELLOW + "  10. SHAKE-256\n" + Style.RESET_ALL
    )

    print(menu)

def main():
    while True:
        display_menu()

        choice = input(f"{Fore.LIGHTBLACK_EX}Enter the number of the algorithm for which you want to hash the password: {Fore.LIGHTWHITE_EX}")

        if choice == '0':
            print(Fore.YELLOW + "Exiting the program. Goodbye!" + Style.RESET_ALL)
            break

        elif choice not in {'1', '2', '3', '4', '5', '6', '7', '8', '9', '10'}:
            print(f"{Fore.LIGHTRED_EX}Invalid choice. Please choose a number between 0 and 10.")
            input("Press enter to continue..")
            continue

        password = input(f"{Fore.LIGHTBLACK_EX}Enter your password: {Fore.LIGHTWHITE_EX}")

        if choice == "1":
            hashed_password = generate_argon2_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nArgon2 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "2":
            hashed_password = generate_bcrypt_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nBCrypt Hash: {Fore.YELLOW}{hashed_password.decode('utf-8')}")
                input("Press enter to continue..")

        elif choice == "3":
            hashed_password = generate_scrypt_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nSCrypt Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "4":
            hashed_password = generate_md5_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nMD5 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "5":
            hashed_password = generate_sha256_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nSHA-256 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "6":
            hashed_password = generate_sha512_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nSHA-512 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "7":
            hashed_password = generate_blake2b_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nBlake2b Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "8":
            hashed_password = generate_pbkdf2_hmac_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nPBKDF2-HMAC Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "9":
            hashed_password = generate_shake128_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nSHAKE-128 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        elif choice == "10":
            hashed_password = generate_shake256_hash(password)
            if hashed_password:
                print(f"{Fore.LIGHTBLUE_EX}\nSHAKE-256 Hash: {Fore.YELLOW}{hashed_password}")
                input("Press enter to continue..")

        else:
            print(f"{Fore.LIGHTRED_EX}Invalid choice. Please choose a number between 0 and 10.")
            input("Press enter to continue..")

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nExiting the program. Goodbye!" + Style.RESET_ALL)