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




