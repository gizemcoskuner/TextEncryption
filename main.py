from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet

root = Tk()
root.title("Text Encryption")
root.minsize(500,600)
root.config(padx=20, pady=20)

img = Image.open("top secret image.jpg")
img = img.resize((150,125))
img = ImageTk.PhotoImage(img)
panel = Label(image=img)
panel.pack(padx=20,pady=20)

title_label = Label(text="Enter Your Title", font=("Times", 15, "normal"))
title_label.pack(padx=5, pady=5)

title_entry = Entry(width=45)
title_entry.pack()

secret_text_label = Label(text="Enter Your Secret", font=("Times", 15, "normal"))
secret_text_label.pack(padx=5, pady=5)

secret_text_entry = Text(width=45, height=10)
secret_text_entry.pack()

key_label = Label(text="Enter Master Key", font=("Times", 15, "normal"))
key_label.pack(padx=5, pady=5)

key_entry = Entry(width=45, show="*")
key_entry.pack()

encryption_key = Fernet.generate_key()

def clear():
    title_entry.delete(0, END)
    secret_text_entry.delete(1.0, END)
    key_entry.delete(0, END)
def encrypt():
    global password
    secret = secret_text_entry.get(1.0, END)
    secret_text_entry.delete(1.0, END)
    cipher_suite = Fernet(encryption_key)
    password = key_entry.get()
    secret = secret.encode()
    secret = cipher_suite.encrypt(secret)
    secret = secret.decode()
    with open("confidential.txt", mode="a") as confidential:
        confidential.write(f"\n{title_entry.get()}")
        confidential.write(f"\n{secret}")
    clear()
def decrypt():
    secret = secret_text_entry.get(1.0, END)
    secret_text_entry.delete(1.0, END)
    cipher_suite = Fernet(encryption_key)

    if key_entry.get() == password:
        secret = secret.encode()
        secret = cipher_suite.decrypt(secret)
        secret = secret.decode()
        secret_text_entry.insert(END, secret)

    else:
        messagebox.showwarning("Incorrect!", "Incorrect Password, Try Again!")
        key_entry.delete(0, END)

encrypt_button = Button(text="Save and Encrypt", bg="white",font=("Times", 12, "normal"), width=15, command=encrypt)
encrypt_button.pack(padx=10, pady=10)

decrypt_button = Button(text="Decrypt", bg="white", font=("Times", 12, "normal"), width=10, command=decrypt)
decrypt_button.pack()


root.mainloop()

