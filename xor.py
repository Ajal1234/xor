import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import secrets
import string

# Generate a secure hash-based header from the key
def generate_header(key):
    return hashlib.sha256(key.encode()).digest()[:16]  # Use 16-byte header

# XOR Encryption/Decryption Function
def xor_cipher(data, key):
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])

# File Selection
def select_file(entry_widget, label_widget):
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        label_widget.config(text=f"Selected: {file_path}")
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, file_path)

# File Processing (Encrypt/Decrypt)
def process_file(mode, file_entry, key_entry, output_text):
    file_path = file_entry.get()
    key = key_entry.get().strip()

    if not file_path or not key:
        messagebox.showerror("Error", "Please select a file and enter a key!")
        return

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        key_header = generate_header(key)

        if mode == "encrypt":
            processed_data = key_header + xor_cipher(file_data, key)
        else:  # Decryption
            if len(file_data) < 16:
                messagebox.showerror("Error", "File is too small or corrupted!")
                return

            extracted_header = file_data[:16]
            encrypted_data = file_data[16:]

            if extracted_header != key_header:
                messagebox.showerror("Error", "Key is incorrect! Decryption failed.")
                return  # Stop the process if the key is wrong

            processed_data = xor_cipher(encrypted_data, key)

        output_file = file_path + (".enc" if mode == "encrypt" else ".dec")

        with open(output_file, "wb") as f:
            f.write(processed_data)

        try:
            output_text.delete("1.0", tk.END)
            output_text.insert("1.0", processed_data.decode("utf-8"))
        except UnicodeDecodeError:
            output_text.delete("1.0", tk.END)
            output_text.insert("1.0", "[Binary Data: Cannot Display]")

        messagebox.showinfo("Success", f"File saved as: {output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to process file: {e}")

# Generate a Random Key
def generate_key(key_entry):
    random_key = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, random_key)

# Toggle Key Visibility
def toggle_key_visibility(key_entry, show_button):
    if key_entry.cget("show") == "*":
        key_entry.config(show="")
        show_button.config(text="Hide Key")
    else:
        key_entry.config(show="*")
        show_button.config(text="Show Key")

# Create Encryption Window
def create_encryption_window():
    root.withdraw()
    enc_window = tk.Toplevel()
    enc_window.title("Encrypt File")
    enc_window.geometry("600x450")
    enc_window.configure(bg="#f0f0f0")

    tk.Label(enc_window, text="Select File to Encrypt:", bg="#f0f0f0", fg="black").pack()
    file_entry = tk.Entry(enc_window, width=50)
    file_entry.pack()
    file_label = tk.Label(enc_window, text="No file selected", fg="gray", bg="#f0f0f0")
    file_label.pack()
    select_button = tk.Button(enc_window, text="Browse", command=lambda: select_file(file_entry, file_label))
    select_button.pack(pady=5)

    tk.Label(enc_window, text="Enter Key:", bg="#f0f0f0", fg="black").pack()
    key_entry = tk.Entry(enc_window, width=40, show="*")
    key_entry.pack()

    key_frame = tk.Frame(enc_window, bg="#f0f0f0")
    key_frame.pack()

    gen_key_button = tk.Button(key_frame, text="Generate Key", command=lambda: generate_key(key_entry))
    gen_key_button.pack(side="left", padx=5)

    show_key_button = tk.Button(key_frame, text="Show Key", command=lambda: toggle_key_visibility(key_entry, show_key_button))
    show_key_button.pack(side="left")

    encrypt_button = tk.Button(enc_window, text="Encrypt", command=lambda: process_file("encrypt", file_entry, key_entry, output_text))
    encrypt_button.pack(pady=5)

    tk.Label(enc_window, text="Encrypted Output:", bg="#f0f0f0", fg="black").pack()
    output_text = tk.Text(enc_window, height=10, width=70, bg="white", fg="black")
    output_text.pack()

    def on_close():
        enc_window.destroy()
        root.deiconify()

    enc_window.protocol("WM_DELETE_WINDOW", on_close)
    enc_window.mainloop()

# Create Decryption Window
def create_decryption_window():
    root.withdraw()
    dec_window = tk.Toplevel()
    dec_window.title("Decrypt File")
    dec_window.geometry("600x450")
    dec_window.configure(bg="#f0f0f0")

    tk.Label(dec_window, text="Select File to Decrypt:", bg="#f0f0f0", fg="black").pack()
    file_entry = tk.Entry(dec_window, width=50)
    file_entry.pack()
    file_label = tk.Label(dec_window, text="No file selected", fg="gray", bg="#f0f0f0")
    file_label.pack()
    select_button = tk.Button(dec_window, text="Browse", command=lambda: select_file(file_entry, file_label))
    select_button.pack(pady=5)

    tk.Label(dec_window, text="Enter Key:", bg="#f0f0f0", fg="black").pack()
    key_entry = tk.Entry(dec_window, width=40, show="*")
    key_entry.pack()

    key_frame = tk.Frame(dec_window, bg="#f0f0f0")
    key_frame.pack()

    show_key_button = tk.Button(key_frame, text="Show Key", command=lambda: toggle_key_visibility(key_entry, show_key_button))
    show_key_button.pack(side="left")

    decrypt_button = tk.Button(dec_window, text="Decrypt", command=lambda: process_file("decrypt", file_entry, key_entry, output_text))
    decrypt_button.pack(pady=5)

    tk.Label(dec_window, text="Decrypted Output:", bg="#f0f0f0", fg="black").pack()
    output_text = tk.Text(dec_window, height=10, width=70, bg="white", fg="black")
    output_text.pack()

    def on_close():
        dec_window.destroy()
        root.deiconify()

    dec_window.protocol("WM_DELETE_WINDOW", on_close)
    dec_window.mainloop()

# Main Application Window
root = tk.Tk()
root.title("XOR File Encryptor/Decryptor")
root.geometry("450x250")
root.configure(bg="#f0f0f0")

tk.Label(root, text="Select an option:", bg="#f0f0f0", fg="black", font=("Arial", 12, "bold")).pack(pady=15)

encrypt_window_button = tk.Button(root, text="Encrypt File", command=create_encryption_window, width=20, height=2)
encrypt_window_button.pack(pady=10)

decrypt_window_button = tk.Button(root, text="Decrypt File", command=create_decryption_window, width=20, height=2)
decrypt_window_button.pack(pady=10)

root.mainloop()