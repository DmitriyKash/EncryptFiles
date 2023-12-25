import pyAesCrypt
import os

# Розмір буфера, використовуваний під час шифрування/дешифрування (64К)
bufferSize = 64 * 1024


def encrypt_file(file_name, password):
    """
    Encrypts a file using AES encryption algorithm.

    Parameters:
        file_name (str): The name of the file to be encrypted.
        password (str): The password used for encryption.

    Returns:
        str: The name of the encrypted file.
    """
    encrypted_file_name = file_name + ".aes"

    with open(file_name, "rb") as fIn:
        with open(encrypted_file_name, "wb") as fOut:
            pyAesCrypt.encryptStream(fIn, fOut, password, bufferSize)

    return encrypted_file_name


def decrypt_file(file_name, password):
    """
    Decrypts a file using a given password.

    Args:
        file_name (str): The name of the file to be decrypted.
        password (str): The password used to decrypt the file.

    Returns:
        str or None: The decrypted file name if successful, None if the password is incorrect.
    """
    decrypted_file_name = os.path.splitext(file_name)[0]

    with open(file_name, "rb") as fIn:
        with open(decrypted_file_name, "wb") as fOut:
            try:
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize, os.path.getsize(file_name))
            except ValueError:
                # Це може статися, якщо пароль неправильний
                return None

    return decrypted_file_name


# Інтерфейс користувача
def main():
    choice = input("Enter '1' to encrypt a file or '2' to decrypt a file: ")
    file_name = input("Enter the filename: ")
    password = input("Enter the password: ")

    if choice == '1':
        encrypted_file = encrypt_file(file_name, password)
        print(f"File encrypted: {encrypted_file}")
    elif choice == '2':
        decrypted_file = decrypt_file(file_name, password)
        if decrypted_file:
            print(f"File decrypted: {decrypted_file}")
        else:
            print("Decryption failed. Incorrect password?")
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
