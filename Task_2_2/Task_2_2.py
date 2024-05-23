from pickle import BINPUT
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt(plaintext, key, mode, iv=None):
    backend = default_backend()
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    else:
        raise ValueError("Invalid mode, choose ECB, CBC, or CFB")

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt(ciphertext, key, mode, iv=None):
    backend = default_backend()
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    else:
        raise ValueError("Invalid mode, choose ECB, CBC, or CFB")

    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=backend)
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def encrypt_menu():
    os.system('cls')
    print(f'Write a plaintext to encrypt: ')
    text = input()
    print(f'Write a key (16 bytes): ')
    while True:
        key = input()
        if len(key) != 16:
            print("wrong lenth. Try again.")
        else:
            break
    
    key = str.encode(key)
    iv = os.urandom(16)
    plaintext = str.encode(text)

    print('')
    print(f'Choose an option (write only number):')
    print(f'(1) ECB Block Cipher')
    print(f'(2) CBC Block Cipher')
    print(f'(3) CFB Block Cipher')
    
    ciphertext = b''
    while True:
        choice = input()
        if choice == '1': 
            ciphertext = encrypt(plaintext, key, 'ECB')
            break
        if choice == '2':
            print(f'Write a iv (16 bytes):')
            while True:
                iv = input()
                if len(iv) != 16:
                    print('Wrong iv lenth. Try again.')
                else:
                    break
            iv = iv.encode()
            ciphertext = encrypt(plaintext, key, 'CBC', iv)
            break
        if choice == '3':
            print(f'Write a iv (16 bytes):')
            while True:
                iv = input()
                if len(iv) != 16:
                    print('Wrong iv lenth. Try again.')
                else:
                    break
            iv = iv.encode()
            ciphertext = encrypt(plaintext, key, 'CFB', iv)
            break
        if choice != '1' and choice != '2' and choice != '3':
            print('There is no such option. Try again.')
    
    print(ciphertext)
    print(f'Write a file name: ')
    file_name = input()
    file_path = 'messages\\' + file_name + '.txt'
    with open(file_path, 'wb') as f:
        f.write(ciphertext)
    

def decrypt_menu():
    os.system('cls')
    
    ciphertext = b''
    
    print('Write a file name to decrypt: ')
    while True:
        file_name = input()
        file_path = 'messages\\' + file_name + '.txt'
        if not os.path.exists(file_path):
            print(f'There is no file named: {file_name}. Try something else.')
        else:
            break
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    print(f'Write a key (16 bytes): ')
    while True:
        key = input()
        if len(key) != 16:
            print("Wrong lenth. Try again.")
        else:
            break
    key = str.encode(key)
    print('')
    print(f'Choose an option (write only number):')
    print(f'(1) ECB Block Cipher')
    print(f'(2) CBC Block Cipher')
    print(f'(3) CFB Block Cipher')
    
    decryptedtext = b''
    while True:
        choice = input()
        if choice == '1': 
            decryptedtext = decrypt(ciphertext, key, 'ECB')
            break
        if choice == '2':
            print(f'Write a iv (16 bytes):')
            while True:
                iv = input()
                if len(iv) != 16:
                    print('Wrong iv lenth. Try again.')
                else:
                    break
            iv = iv.encode()
            decryptedtext = decrypt(ciphertext, key, 'CBC', iv)
            break
        if choice == '3':
            print(f'Write a iv (16 bytes):')
            while True:
                iv = input()
                if len(iv) != 16:
                    print('Wrong iv lenth. Try again.')
                else:
                    break
            iv = iv.encode()
            decryptedtext = decrypt(ciphertext, key, 'CFB', iv)
            break
        if choice != '1' and choice != '2' and choice != '3':
            print('There is no such option. Try again.')
    
    print('Decoded text: ', decryptedtext.decode('utf-8'))

def menu():
    while True:
        os.system('cls')
        print(f'Choose an option (write only number):')
        print(f'(1) Encrypt message')
        print(f'(2) Decrypt message')
        print(f'(3) End program')
        choice = ''
        
        while True:
            choice = input()
            if choice == '1': 
                encrypt_menu()
                break
            if choice == '2':
                decrypt_menu()
                break
            if choice == '3':
                break
            if choice != '1' and choice != '2' and choice != '3':
                print('There is no such option. Try again.')
        if choice == '3':
            break

if __name__ == "__main__":
    newpath = r'messages'
    if not os.path.exists(newpath):
        os.makedirs(newpath)
        
    menu()
    
    # Encrypt and decrypt in ECB mode
    #ciphertext_ecb = encrypt(plaintext, key, 'ECB')
    #print("ECB Encrypted:", ciphertext_ecb)
    #decryptedtext_ecb = decrypt(ciphertext_ecb, key, 'ECB')
    #print("ECB Decrypted:", decryptedtext_ecb)

    # Encrypt and decrypt in CBC mode
    #ciphertext_cbc = encrypt(plaintext, key, 'CBC', iv)
    #print("CBC Encrypted:", ciphertext_cbc)
    #decryptedtext_cbc = decrypt(ciphertext_cbc, key, 'CBC', iv)
    #print("CBC Decrypted:", decryptedtext_cbc)

    # Encrypt and decrypt in CFB mode
    #ciphertext_cfb = encrypt(plaintext, key, 'CFB', iv)
    #print("CFB Encrypted:", ciphertext_cfb)
    #decryptedtext_cfb = decrypt(ciphertext_cfb, key, 'CFB', iv)
    #print("CFB Decrypted:", decryptedtext_cfb)
