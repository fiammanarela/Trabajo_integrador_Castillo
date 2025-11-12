import customtkinter as ctk
from tkinter import messagebox
import random

# CIFRADO XOR
def xor_cifrado(texto, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(texto))

