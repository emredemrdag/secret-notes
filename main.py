from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def encrypt_notes():
    title = title_entry.get()
    message = secret_text.get("1.0", END)
    master_secret = masterKey_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showwarning(title="error!", message="please enter all info.")
    else:
        message_encrypted = encode(master_secret, message)
        try:
            with open ("secret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open ("secret.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            masterKey_entry.delete(0, END)
            secret_text.delete("1.0", END)


def decrypt_notes():
    message_encrypted = secret_text.get("1.0", END)
    master_secret = masterKey_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showwarning(title="error!", message="please enter all info.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showwarning(title="error!", message="please enter encrypted text.")


window = Tk()
window.title("secret notes")
window.config(padx=30, pady=30)

photo = PhotoImage(file="silence .png")
photo_label = Label(image=photo)
photo_label.pack()

title_label = Label(text="enter your title", font=('arial', 10))
title_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

secret_label = Label(text="enter your secret", font=('arial', 10))
secret_label.pack()

secret_text = Text(width=50, height=10)
secret_text.pack()

masterKey = Label(text="enter master key", font=('arial', 10))
masterKey.pack()

masterKey_entry = Entry(width=30)
masterKey_entry.pack()

encrypt_button = Button(text="save & encrypt", command=encrypt_notes)
encrypt_button.pack()

decrypt_button = Button(text="decrypt", command=decrypt_notes)
decrypt_button.pack()

window.mainloop()
