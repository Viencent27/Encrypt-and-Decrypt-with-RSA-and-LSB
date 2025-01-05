import streamlit as st
from math import gcd
import random
from sympy import isprime
from cryptography.fernet import Fernet
import base64, hashlib
from PIL import Image

# Fungsi untuk membuat kunci RSA
def generate_rsa_keys(p, q):
  # Menghitung nilai n dan m
  n = p * q
  m = (p - 1) * (q - 1)
  
  # Mencari nilai e (relatif prima dengan m)
  e = random.choice([x for x in range(2, m) if gcd(x, m) == 1])
  
  # Mencari nilai d (invers modular dari e mod m (rumus awal e*d mod m = 1))
  d = pow(e, -1, m)
  
  return e, d, n

# Fungsi untuk mengenkripsi plaintext dengan algoritma RSA
def encrypt_rsa(plain, e, n):
  # Menggunakan rumus M^e mod n
  cipher = [pow(ord(char), e, n) for char in plain]
  
  return cipher

# Fungsi untuk mendekripsi ciphertext dengan algoritma RSA
def decrypt_rsa(cipher, d, n):
  # Menggunakan rumus C^d mod n
  plain = [chr(pow(char, d, n)) for char in cipher]
  
  return ''.join(plain)

def encrypt_file(key, e, d, n):
  f = Fernet(key)
  data = f'{e}\n{d}\n{n}'
  # encrypt data
  encrypted_data = f.encrypt(str.encode(data))
  
  return encrypted_data

def decrypt_file(encrypted_data, key):
  f = Fernet(key)
  # decrypt data
  decrypted_data = f.decrypt(encrypted_data)
  e, d, n = decrypted_data.split(b"\n", 2)
  return int(e), int(d), int(n)

# Fungsi untuk menyisipkan pesan ke dalam gambar (LSB)
def embed_message_to_image(image, rsa_message, output_path):
  img = Image.open(image).convert("RGBA")
  pixels = img.getdata()
  message_bits = ''.join(format(ord(char), '08b') for char in rsa_message) + '00000000'
  new_pixels = []
  message_index = 0

  for pixel in pixels:
    r, g, b, a = pixel
    if message_index < len(message_bits):
      new_r = (r & ~1) | int(message_bits[message_index])
      message_index += 1
    else:
      new_r = r
    new_pixels.append((new_r, g, b, a))
  
  img.putdata(new_pixels)
  img.save(output_path)
  return output_path

# Fungsi untuk mengambil pesan dari gambar (LSB)
def extract_message_from_image(image):
  img = Image.open(image).convert("RGBA")
  pixels = img.getdata()
  message_bits = []
  
  for pixel in pixels:
    r, _, _, _ = pixel
    message_bits.append(str(r & 1))
    if len(message_bits) >= 8 and ''.join(message_bits[-8:]) == '00000000':
      break
  
  message = ''.join(chr(int(''.join(message_bits[i:i+8]), 2)) for i in range(0, len(message_bits) - 8, 8))
  return message

# Streamlit GUI
def main():
  # Initialize Session State
  if "private_key" not in st.session_state:
    st.session_state.private_key = None
  if "public_key" not in st.session_state:
    st.session_state.public_key = None
  if "n" not in st.session_state:
    st.session_state.n = None

  st.title("Aplikasi Enkripsi Dekripsi Menggunakan RSA dan LSB")

  # Menu
  menu = st.sidebar.selectbox("Menu", ["Buat Kunci RSA", "Upload Kunci", "Enkripsi", "Dekripsi"])

  if menu == "Buat Kunci RSA":
    st.header("Buat Kunci RSA")
    prime1 = st.number_input("Masukkan bilangan prima pertama:", min_value=2, step=1)
    prime2 = st.number_input("Masukkan bilangan prima kedua:", min_value=2, step=1)
    password = st.text_input("Masukkan Password untuk Melindungi Kunci", type="password")
    if st.button("Buat Kunci"):
      if not isprime(prime1) or not isprime(prime2):
        raise ValueError("Bilangan yang dimasukkan harus bilangan prima!")
      if prime1 == prime2:
        raise ValueError("Bilangan prima tidak boleh sama!")
      if password and prime1 and prime2:
        if prime1 * prime2 > 122:
          public_key, private_key, n = generate_rsa_keys(prime1, prime2)
          st.session_state.public_key = public_key
          st.session_state.private_key = private_key
          st.session_state.n = n
          key = hashlib.md5(password.encode()).hexdigest()
          key_64 = base64.urlsafe_b64encode(key.encode("utf-8"))
          data = encrypt_file(key_64, public_key, private_key, n)
          st.write("kunci publik: ", public_key)
          st.write("kunci privat: ", private_key)
          st.success("Kunci berhasil dibuat!")
          st.download_button("Unduh Kunci", data=data, file_name="rsa_key.key")
        else:
          st.error("Hasil perkalian bilangan prima harus lebih dari 122")
      else:
        st.error("Bilangan prima dan password tidak boleh kosong.")

  elif menu == "Upload Kunci":
    st.header("Upload Kunci")
    key_file = st.file_uploader("Unggah File Kunci RSA", type=["key"])
    password = st.text_input("Masukkan Password untuk Membuka Kunci", type="password")
    if st.button("Ekstrak Kunci"):
      if key_file and password:
        try:
          key = hashlib.md5(password.encode()).hexdigest()
          key_64 = base64.urlsafe_b64encode(key.encode("utf-8"))
          public_key, private_key, n = decrypt_file(key_file.read(), key_64)
          st.session_state.public_key = public_key
          st.session_state.private_key = private_key
          st.session_state.n = n
          st.write("kunci publik: ", public_key)
          st.write("kunci privat: ", private_key)
          st.success("Kunci berhasil dimuat!")
        except Exception as e:
          st.error("Gagal memuat kunci: " + str(e))
      else:
        st.error("File dan password diperlukan.")

  elif menu == "Enkripsi":
    st.header("Enkripsi Pesan")
    message = st.text_area("Masukkan Pesan Rahasia")
    image_file = st.file_uploader("Unggah Gambar (PNG)", type=["png"])
    if st.button("Enkripsi dan Sisipkan Pesan"):
      if message and image_file:
        if st.session_state.public_key:
          try:
            rsa_message = encrypt_rsa(message, st.session_state.public_key, st.session_state.n)
            embed_message_to_image(image_file, ' '.join(str(char) for char in rsa_message), "encrypted_image.png")
            st.success("Pesan berhasil disisipkan ke gambar!")
            st.download_button("Unduh Gambar Terenkripsi", data=open("encrypted_image.png", "rb"), file_name="encrypted_image.png", mime="image/png")
          except Exception as e:
            st.error("Gagal mengenkripsi: " + str(e))
        else:
          st.error("Kunci diperlukan.")
      else:
        st.error("Pesan dan gambar diperlukan.")

  elif menu == "Dekripsi":
    st.header("Dekripsi Pesan")
    encrypted_image = st.file_uploader("Unggah Gambar dengan Pesan Tersembunyi (PNG)", type=["png"])
    if st.button("Dekripsi"):
      if encrypted_image:
        if st.session_state.private_key:
          try:
            hidden_message = extract_message_from_image(encrypted_image)
            message = decrypt_rsa([int(char) for char in hidden_message.split(' ')], st.session_state.private_key, st.session_state.n)
            st.success("Pesan berhasil didekripsi:")
            st.text(message)
          except Exception as e:
            st.error("Gagal mendekripsi: " + str(e))
        else:
          st.error("Kunci diperlukan.")
      else:
        st.error("Gambar diperlukan.")

if __name__ == "__main__":
  main()
