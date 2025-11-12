import customtkinter as ctk
from tkinter import messagebox
import random

# CIFRADO XOR
def xor_cifrado(texto, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(texto))

# CIFRADO CESAR
def cesar_cifrado(texto, key, decrypt=False):
    try:
        shift = int(key) % 26
    except:
        return "La clave debe ser un número"
    if decrypt:
        shift = -shift
    result = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

# CIFRADO VIGENERE
def vigenere_cifrado(texto, key, decrypt=False):
    resultado = ''
    if not key.isalpha():
        return "La clave debe contener solo letras"
    key = key.lower()
    key_index = 0
    for char in texto:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if decrypt:
                shift = -shift
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            resultado += char
    return resultado




