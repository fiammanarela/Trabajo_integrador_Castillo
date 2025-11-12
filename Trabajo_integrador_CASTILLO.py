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


# PLAYFAIR
def matriz(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()
    for char in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in used and char.isalpha():
            matrix.append(char)
            used.add(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]


def posicion(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None, None


def playfair_cifrado(text, key, decrypt=False):
    matrix = matriz(key)
    text = text.upper().replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = 'X'
        if i + 1 < len(text) and text[i + 1] != a:
            b = text[i + 1]
            i += 1
        pairs.append(a + b)
        i += 1

    result = ""
    for pair in pairs:
        r1, c1 = posicion(matrix, pair[0])
        r2, c2 = posicion(matrix, pair[1])
        if r1 == r2:
            if decrypt:
                result += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
            else:
                result += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            if decrypt:
                result += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
            else:
                result += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]

    return result

# DIFFIE-HELLMAN 

def diffie_hellman(p=23, g=5, a=6, b=15):
    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_A = pow(B, a, p)
    shared_B = pow(A, b, p)

    texto = f""" Intercambio Diffie-Hellman

Valores públicos:
  p (primo) = {p}
  g (base) = {g}

Claves privadas:
  a (Alice) = {a}
  b (Bob) = {b}

Claves públicas generadas:
  A = g^a mod p = {A}
  B = g^b mod p = {B}

Cálculo de clave compartida:
  Alice: (B^a mod p) = {shared_A}
  Bob:   (A^b mod p) = {shared_B}

Resultado final:
  Clave compartida = {shared_A}
"""
    return texto


# RSA
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    for d in range(3, phi):
        if (e * d) % phi == 1:
            return d
    return None


def rsa_generate_keys():
    p = 17
    q = 11
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(text, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in text]


def rsa_decrypt(cipher, private_key):
    d, n = private_key
    return ''.join(chr(pow(char, d, n)) for char in cipher)

# INTERFAZ

def process_text():
    algorithm = combo_algo.get()
    text = textbox_input.get("1.0", "end").strip()
    key = entry_key.get().strip()
    decrypt = switch_var.get()

    if not text and algorithm not in ["Diffie-Hellman", "RSA"]:
        messagebox.showerror("Error", "Debe ingresar un texto.")
        return

    try:
        if algorithm == "Cifrado XOR":
            if not key:
                messagebox.showerror("Error", "Debe ingresar una clave.")
                return
            result = xor_cifrado(text, key)

        elif algorithm == "Cifrado César":
            result = cesar_cifrado(text, key, decrypt)

        elif algorithm == "Cifrado Vigenere":
            result = vigenere_cifrado(text, key, decrypt)

        elif algorithm == "Cifrado Playfair":
            result = playfair_cifrado(text, key, decrypt)

        elif algorithm == "Diffie-Hellman":
            result = diffie_hellman(23, 5, 6, 15)

        elif algorithm == "RSA":
            public, private = rsa_generate_keys()
            if decrypt:
                cipher_nums = [int(x) for x in text.split()]
                result = rsa_decrypt(cipher_nums, private)
            else:
                cipher = rsa_encrypt(text, public)
                result = ' '.join(map(str, cipher))

        else:
            result = "Algoritmo no reconocido."

        textbox_output.delete("1.0", "end")
        textbox_output.insert("end", result)

    except Exception as e:
        messagebox.showerror("Error", str(e))



ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("🔐 App de Cifrados - Versión Mejorada")
app.geometry("750x680")

ctk.CTkLabel(app, text="Aplicación de Cifrados", font=("Arial Rounded MT Bold", 24)).pack(pady=10)

frame_top = ctk.CTkFrame(app)
frame_top.pack(pady=10)

ctk.CTkLabel(frame_top, text="Seleccione algoritmo:", font=("Arial", 16)).pack(side="left", padx=10)
combo_algo = ctk.CTkComboBox(frame_top, values=[
    "Cifrado XOR", "Cifrado César", "Cifrado Vigenere",
    "Cifrado Playfair", "Diffie-Hellman", "RSA"
])
combo_algo.set("Cifrado XOR")
combo_algo.pack(side="left", padx=10)

ctk.CTkLabel(app, text="Texto:", font=("Arial", 14)).pack()
textbox_input = ctk.CTkTextbox(app, height=100, width=650)
textbox_input.pack(pady=5)

ctk.CTkLabel(app, text="Clave (si aplica):", font=("Arial", 14)).pack()
entry_key = ctk.CTkEntry(app, width=400, placeholder_text="Ingrese la clave aquí")
entry_key.pack(pady=5)

switch_var = ctk.BooleanVar()
ctk.CTkSwitch(app, text="Descifrar", variable=switch_var, onvalue=True, offvalue=False).pack(pady=5)

ctk.CTkButton(app, text="Procesar", command=process_text, width=200, height=40, corner_radius=12, fg_color="#0078D7").pack(pady=15)

ctk.CTkLabel(app, text="Resultado:", font=("Arial", 14)).pack()
textbox_output = ctk.CTkTextbox(app, height=180, width=650)
textbox_output.pack(pady=5)

ctk.CTkLabel(app, text="Castillo Rossi Fiamma", font=("Arial", 12)).pack(pady=10)

app.mainloop()
