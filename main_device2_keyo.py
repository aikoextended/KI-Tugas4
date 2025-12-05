# file name: main_device2_keyo_signature.py
# file content begin
# main_device2_keyo_signature.py - DEVICE 2 (Keyo) dengan Signature hanya pada RSA

import rsa_enhanced as rsa
import des
from http_handler import HTTPCommunicator
import time
import json

class DeviceKeyoSignature:
    def __init__(self):
        self.name = "Keyo"
        self.private_key = None
        self.public_key = None
        self.communicator = HTTPCommunicator(port=8080)
        self.other_device_ip = None
        self.other_public_key = None
        self.session_data = {}
        self.handshake_stage = 0
        self.des_mode = False
        self.is_initiator = False
        
    def load_keys(self):
        """Load private dan public key"""
        p, q = 107, 109  # n = 11663
        self.public_key, self.private_key = rsa.generate_keypair(p, q)
        print(f"✓ Key pair loaded - Public: {rsa.format_public_key(self.public_key)}")
        
        # Simpan public key ke directory
        self.save_public_key_to_directory()
        
    def save_public_key_to_directory(self):
        """Menyimpan public key ke public directory"""
        import os
        os.makedirs('public_directory', exist_ok=True)
        
        with open(f'public_directory/{self.name.lower()}.txt', 'w') as f:
            f.write(rsa.format_public_key(self.public_key))
        print(f"✓ Public key disimpan ke public_directory/{self.name.lower()}.txt")
    
    def read_public_key_from_directory(self, username):
        """Membaca public key dari public directory"""
        try:
            with open(f'public_directory/{username.lower()}.txt', 'r') as f:
                key_content = f.read().strip()
                print(f"✓ Public key {username} ditemukan")
                return rsa.parse_public_key(key_content)
        except Exception as e:
            print(f"✗ File public_directory/{username.lower()}.txt tidak ditemukan! Error: {e}")
            return None
    
    def handle_incoming_message(self, data):
        """Callback untuk menangani pesan masuk"""
        msg_type = data.get('type')
        sender = data.get('sender', 'Unknown')
        
        print(f"\n{'='*50}")
        print(f"Pesan Dari {sender}")
        print(f"{'='*50}")
        
        if msg_type == 'N1_encrypted_signed':
            """Fase 1: Menerima N1 dengan signature (RSA dengan signature)"""
            if self.is_initiator:
                print("✗ Sudah menjadi initiator, tidak bisa menerima N1")
                return {'status': 'error'}
            
            print("🔐 FASE RSA DENGAN SIGNATURE")
            
            # Ambil public key pengirim
            sender_public_key = self.read_public_key_from_directory(sender)
            if not sender_public_key:
                print("✗ Tidak dapat memverifikasi: Public key tidak ditemukan")
                return {'status': 'error'}
            
            encrypted_n1 = data['ciphertext']
            signature = data['signature']
            timestamp = data.get('timestamp', '')
            
            print(f"N1 Ciphertext: {encrypted_n1}")
            print(f"Signature: {signature}")
            print(f"Timestamp: {timestamp}")
            
            # Dekripsi N1
            print("\n📝 Deskripsi N1:")
            try:
                decrypted_n1 = rsa.decrypt(self.private_key, encrypted_n1)
                print(f"N1 Plaintext: {decrypted_n1}")
                
                # Verifikasi signature
                is_valid = rsa.verify_signature_rsa(sender_public_key, decrypted_n1, signature)
                
                if is_valid:
                    print(f"✅ SIGNATURE VALID dari {sender}")
                    self.session_data['N1_received'] = decrypted_n1
                    self.session_data['sender'] = sender
                    self.handshake_stage = 2
                    self.other_public_key = sender_public_key
                    print("✓ N1 berhasil diverifikasi dengan signature. Pilih menu [2] untuk melanjutkan.")
                else:
                    print("❌ SIGNATURE INVALID! Pesan mungkin dimodifikasi")
                    self.handshake_stage = 0
                
            except Exception as e:
                print(f"✗ Error dekripsi N1: {e}")
            
            return {'status': 'received'}
        
        elif msg_type == 'N1_N2_response_signed':
            """Fase 2: Menerima respons N1+N2 dengan signature (RSA dengan signature)"""
            if not self.is_initiator:
                print("✗ Bukan initiator, tidak bisa menerima N1_N2 response")
                return {'status': 'error'}
            
            print("🔐 FASE RSA DENGAN SIGNATURE")
            
            # Ambil public key pengirim
            sender_public_key = self.read_public_key_from_directory(sender)
            if not sender_public_key:
                print("✗ Tidak dapat memverifikasi: Public key tidak ditemukan")
                return {'status': 'error'}
            
            received_n1 = data['N1_plaintext']
            encrypted_n2 = data['N2_ciphertext']
            signature = data['signature']
            timestamp = data.get('timestamp', '')
            
            print(f"N1 Plaintext: {received_n1}")
            print(f"N2 Ciphertext: {encrypted_n2}")
            print(f"Signature: {signature}")
            print(f"Timestamp: {timestamp}")
            
            # Verifikasi signature
            message_to_verify = f"{received_n1}:{encrypted_n2}"
            is_valid = rsa.verify_signature_rsa(sender_public_key, message_to_verify, signature)
            
            if not is_valid:
                print("❌ SIGNATURE INVALID! Pesan mungkin dimodifikasi")
                return {'status': 'error', 'reason': 'invalid_signature'}
            
            print(f"✅ SIGNATURE VALID dari {sender}")
            
            # Verifikasi N1
            stored_n1 = self.session_data.get('N1_sent', '')
            print(f"\n🔍 Memverifikasi N1: '{received_n1}' == '{stored_n1}'")
            
            if received_n1 == stored_n1:
                print(f"✅ VERIFIKASI N1 BERHASIL! {sender} terautentikasi!")
                
                # Dekripsi N2
                print("\n📝 Deskripsi N2:")
                try:
                    decrypted_n2 = rsa.decrypt(self.private_key, encrypted_n2)
                    print(f"N2 Plaintext: {decrypted_n2}")
                    self.session_data['N2_received'] = decrypted_n2
                    self.handshake_stage = 3
                    print("✓ N2 berhasil didekripsi. Silakan pilih menu [3] untuk melanjutkan.")
                    
                except Exception as e:
                    print(f"✗ Error dekripsi N2: {e}")
            else:
                print(f"❌ VERIFIKASI N1 GAGAL!")
            
            return {'status': 'received'}
        
        elif msg_type == 'N2_plaintext_signed':
            """Fase 3: Menerima N2 dengan signature (RSA dengan signature)"""
            if self.is_initiator:
                print("✗ Initiator tidak bisa menerima N2 plaintext")
                return {'status': 'error'}
            
            print("🔐 FASE RSA DENGAN SIGNATURE")
            
            # Ambil public key pengirim
            sender_public_key = self.read_public_key_from_directory(sender)
            if not sender_public_key:
                print("✗ Tidak dapat memverifikasi: Public key tidak ditemukan")
                return {'status': 'error'}
            
            received_n2 = str(data['N2_plaintext'])
            signature = data['signature']
            timestamp = data.get('timestamp', '')
            
            print(f"N2 Plaintext: {received_n2}")
            print(f"Signature: {signature}")
            print(f"Timestamp: {timestamp}")
            
            # Verifikasi signature
            is_valid = rsa.verify_signature_rsa(sender_public_key, received_n2, signature)
            
            if not is_valid:
                print("❌ SIGNATURE INVALID! Pesan mungkin dimodifikasi")
                return {'status': 'error', 'reason': 'invalid_signature'}
            
            print(f"✅ SIGNATURE VALID dari {sender}")
            
            # Verifikasi N2
            stored_n2 = str(self.session_data.get('N2_sent', ''))
            print(f"\n🔍 Memverifikasi N2: '{received_n2}' == '{stored_n2}'")
            
            if received_n2 == stored_n2:
                print(f"✅ VERIFIKASI N2 BERHASIL! {sender} terautentikasi!")
                self.handshake_stage = 4
                print("✓ Verifikasi berhasil. Silakan pilih menu [4] untuk mengirim Secret Key.")
            else:
                print(f"❌ VERIFIKASI N2 GAGAL!")
            
            return {'status': 'received'}
        
        elif msg_type == 'secret_key_signed':
            """Fase 4: Menerima secret key dengan signature (RSA dengan signature)"""
            if not self.is_initiator:
                print("✗ Bukan initiator, tidak bisa menerima secret key")
                return {'status': 'error'}
            
            print("🔐 FASE RSA DENGAN SIGNATURE")
            
            # Ambil public key pengirim
            sender_public_key = self.read_public_key_from_directory(sender)
            if not sender_public_key:
                print("✗ Tidak dapat memverifikasi: Public key tidak ditemukan")
                return {'status': 'error'}
            
            secret_key = data['secret_key']
            signature = data['signature']
            timestamp = data.get('timestamp', '')
            
            print(f"Secret Key: {secret_key}")
            print(f"Signature: {signature}")
            print(f"Timestamp: {timestamp}")
            
            # Verifikasi signature
            is_valid = rsa.verify_signature_rsa(sender_public_key, secret_key, signature)
            
            if not is_valid:
                print("❌ SIGNATURE INVALID! Secret key mungkin dimodifikasi")
                return {'status': 'error', 'reason': 'invalid_signature'}
            
            print(f"✅ SIGNATURE VALID dari {sender}")
            
            self.session_data['secret_key'] = secret_key
            print("\n" + "="*50)
            print("✅ SECRET KEY DITERIMA DENGAN SIGNATURE VALID")
            print("🔓 Switching to DES Mode (TANPA SIGNATURE)")
            print("="*50)
            self.des_mode = True
            self.start_des_communication()
            
            return {'status': 'received'}
        
        elif msg_type == 'des_message':
            """Fase 5: Menerima pesan DES (TANPA SIGNATURE)"""
            if not self.des_mode:
                print("🔓 Switching to DES Mode (TANPA SIGNATURE)")
                self.des_mode = True
            
            print("\n" + "="*50)
            print("🔓 FASE DES (TANPA SIGNATURE)")
            print("="*50)
            
            ciphertext = data['ciphertext']
            print(f"DES Ciphertext: {ciphertext}")
            
            secret_key = self.session_data.get('secret_key')
            if secret_key:
                print(f"🔑 Secret Key: {secret_key}")
                try:
                    plaintext = des.des_decrypt(ciphertext, secret_key)
                    print(f"📝 Plaintext: {plaintext}")
                    print("⚠ PERHATIAN: DES tanpa signature - integrity tidak diverifikasi")
                except Exception as e:
                    print(f"✗ Error dekripsi: {e}")
            else:
                print("✗ Secret key belum tersedia!")
            
            return {'status': 'received'}
        
        return {'status': 'ok'}
    
    def send_n1_encrypted_signed(self):
        """Menu 1: Kirim N1 encrypted dengan signature (RSA dengan signature)"""
        if self.is_initiator:
            print("✗ Sudah menjadi initiator, tidak bisa mengirim N1 lagi")
            return
        
        print("\n" + "="*50)
        print("🔐 KIRIM N1 DENGAN SIGNATURE (RSA)")
        print("="*50)
        
        other_name = input("Public key (nama device penerima): ").strip()
        other_public_key = self.read_public_key_from_directory(other_name)
        
        if not other_public_key:
            print("✗ Gagal mendapatkan public key")
            return
        
        n1_plain = input("Kirim N1 Plaintext (1 karakter): ").strip()
        if len(n1_plain) != 1:
            print("✗ N1 harus 1 karakter!")
            return
        
        self.session_data['N1_sent'] = n1_plain
        self.other_public_key = other_public_key
        
        try:
            # Enkripsi N1
            encrypted_n1 = rsa.encrypt(other_public_key, n1_plain)
            
            # Buat signature
            signature = rsa.sign_message_rsa(self.private_key, n1_plain)
            
            # Kirim
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N1_encrypted_signed',
                'sender': self.name,
                'ciphertext': encrypted_n1,
                'signature': signature,
                'timestamp': int(time.time())
            })
            
            print(f"\n✅ N1 dengan signature berhasil dikirim")
            print(f"N1 Plaintext: {n1_plain}")
            print(f"N1 Ciphertext: {encrypted_n1}")
            print(f"Signature: {signature}")
            print("\n⚠ PERHATIAN: RSA dengan signature, DES nanti tanpa signature")
            
            self.handshake_stage = 1
            self.is_initiator = True
            
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_n1_n2_response_signed(self):
        """Menu 2: Kirim N1 plaintext + N2 encrypted dengan signature (RSA dengan signature)"""
        if self.is_initiator:
            print("✗ Initiator tidak bisa mengirim N1_N2 response")
            return
        
        if self.handshake_stage < 2:
            print("✗ Belum menerima N1. Tunggu pesan N1 terlebih dahulu.")
            return
        
        print("\n" + "="*50)
        print("🔐 KIRIM RESPONS N1+N2 DENGAN SIGNATURE (RSA)")
        print("="*50)
        
        if not self.other_public_key:
            print("✗ Public key pengirim tidak tersedia")
            return
        
        n2_plain = input("Kirim N2 Plaintext (1 karakter): ").strip()
        if len(n2_plain) != 1:
            print("✗ N2 harus 1 karakter!")
            return
        
        self.session_data['N2_sent'] = n2_plain
        
        try:
            # Enkripsi N2
            encrypted_n2 = rsa.encrypt(self.other_public_key, n2_plain)
            
            # Buat signature untuk N1 dan encrypted N2
            message_to_sign = f"{self.session_data['N1_received']}:{encrypted_n2}"
            signature = rsa.sign_message_rsa(self.private_key, message_to_sign)
            
            # Kirim
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N1_N2_response_signed',
                'sender': self.name,
                'N1_plaintext': str(self.session_data['N1_received']),
                'N2_ciphertext': encrypted_n2,
                'signature': signature,
                'timestamp': int(time.time())
            })
            
            print(f"\n✅ N1 dan N2 dengan signature berhasil dikirim")
            print(f"N1 Plaintext: {self.session_data['N1_received']}")
            print(f"N2 Plaintext: {n2_plain}")
            print(f"N2 Ciphertext: {encrypted_n2}")
            print(f"Signature: {signature}")
            
            self.handshake_stage = 3
            
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_n2_plaintext_signed(self):
        """Menu 3: Kirim N2 plaintext dengan signature (RSA dengan signature)"""
        if not self.is_initiator:
            print("✗ Responder tidak bisa mengirim N2 plaintext")
            return
        
        if self.handshake_stage < 3:
            print("✗ Belum memverifikasi N1 dan mendapatkan N2.")
            return
        
        print("\n" + "="*50)
        print("🔐 KIRIM N2 DENGAN SIGNATURE (RSA)")
        print("="*50)
        
        if not self.other_public_key:
            print("✗ Public key responder tidak tersedia")
            return
        
        try:
            n2_received = str(self.session_data['N2_received'])
            
            # Buat signature untuk N2
            signature = rsa.sign_message_rsa(self.private_key, n2_received)
            
            # Kirim
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N2_plaintext_signed',
                'sender': self.name,
                'N2_plaintext': n2_received,
                'signature': signature,
                'timestamp': int(time.time())
            })
            
            print(f"\n✅ N2 dengan signature berhasil dikirim")
            print(f"N2 Plaintext: {n2_received}")
            print(f"Signature: {signature}")
            
            self.handshake_stage = 4
            print("\n⏳ Menunggu secret key dari responder...")
            
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_secret_key_signed(self):
        """Menu 4: Kirim Secret Key dengan signature (RSA dengan signature)"""
        if self.is_initiator:
            print("✗ Initiator tidak bisa mengirim secret key")
            return
        
        if self.handshake_stage < 4:
            print("✗ Belum verifikasi lengkap.")
            return
        
        print("\n" + "="*50)
        print("🔐 KIRIM SECRET KEY DENGAN SIGNATURE (RSA)")
        print("="*50)
        
        if not self.other_public_key:
            print("✗ Public key initiator tidak tersedia")
            return
        
        secret_key = input("Kirim Secret Key (1-8 karakter): ").strip()
        if len(secret_key) > 8:
            print("⚠ Secret key maksimal 8 karakter! Menggunakan 8 karakter pertama.")
            secret_key = secret_key[:8]
        
        if not secret_key:
            print("✗ Secret key tidak boleh kosong!")
            return
        
        print(f"Secret Key: '{secret_key}' (panjang: {len(secret_key)} karakter)")
        
        try:
            # Simpan secret key lokal
            self.session_data['secret_key'] = secret_key
            
            # Buat signature untuk secret key
            signature = rsa.sign_message_rsa(self.private_key, secret_key)
            
            # Kirim
            self.communicator.send_message(self.other_device_ip, {
                'type': 'secret_key_signed',
                'sender': self.name,
                'secret_key': secret_key,
                'signature': signature,
                'timestamp': int(time.time())
            })
            
            print(f"\n✅ Secret Key dengan signature berhasil dikirim")
            print(f"Secret Key: {secret_key}")
            print(f"Signature: {signature}")
            print("\n" + "="*50)
            print("✅ BERHASIL: RSA dengan signature SELESAI")
            print("🔓 SEKARANG: Switching to DES Mode (TANPA SIGNATURE)")
            print("="*50)
            
            self.des_mode = True
            self.start_des_communication()
            
        except Exception as e:
            print(f"✗ Gagal mengirim secret key: {e}")
    
    def start_des_communication(self):
        """Mulai komunikasi DES (TANPA SIGNATURE)"""
        print("\n" + "="*60)
        print("MODE KOMUNIKASI DES (TANPA DIGITAL SIGNATURE)")
        print("="*60)
        print("Ketik pesan DES atau 'exit' untuk keluar")
        print("="*60)
        
        while self.des_mode:
            try:
                plaintext = input("\nMasukkan plaintext (atau 'exit' untuk keluar): ").strip()
                
                if plaintext.lower() == 'exit':
                    break
                
                if not plaintext:
                    continue
                    
                secret_key = self.session_data.get('secret_key')
                if not secret_key:
                    print("✗ Secret key belum tersedia!")
                    continue
                
                print(f"🔑 Secret Key: {secret_key}")
                
                # Enkripsi dengan DES
                ciphertext = des.des_encrypt(plaintext, secret_key)
                print(f"🔒 Ciphertext: {ciphertext}")
                
                # Kirim (TANPA SIGNATURE)
                self.communicator.send_message(self.other_device_ip, {
                    'type': 'des_message',
                    'sender': self.name,
                    'ciphertext': ciphertext
                })
                
                print("✅ Ciphertext berhasil dikirim")
                print("⚠ PERHATIAN: DES tanpa signature - integrity tidak diverifikasi")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"✗ Error: {e}")
    
    def show_menu(self):
        """Tampilkan menu utama"""
        print("\n" + "="*50)
        print(f"DEVICE 2 - KEYO")
        print("HYBRID PROTOCOL: RSA with Signature → DES without Signature")
        print("="*50)
        
        if self.des_mode:
            return
        
        # Header dengan status
        role = "Initiator" if self.is_initiator else "Responder"
        mode = "🔐 RSA WITH SIGNATURE"
        print(f"Status: {role} | {mode} | Stage: {self.handshake_stage}")
        
        if self.handshake_stage == 0 and not self.is_initiator:
            print("[1] Kirim N1 encrypted dengan signature (jadikan initiator)")
            print("[9] Keluar")
            
        elif self.is_initiator:
            if self.handshake_stage == 1:
                print("⏳ Menunggu respons N1_N2 dengan signature...")
            elif self.handshake_stage == 3:
                print("[3] Kirim N2 dengan signature (verifikasi)")
            elif self.handshake_stage == 4:
                print("⏳ Menunggu secret key dengan signature dari responder...")
            print("[9] Keluar")
            
        else:
            if self.handshake_stage == 2:
                print("[2] Kirim N1 + N2 encrypted dengan signature (respons)")
            elif self.handshake_stage == 4:
                print("[4] Kirim Secret Key dengan signature")
            print("[9] Keluar")
        
        print("="*50)
    
    def run(self):
        """Menjalankan device"""
        print("="*60)
        print("DEVICE 2 - KEYO")
        print("HYBRID SECURITY PROTOCOL")
        print("="*60)
        print("Fase 1: RSA dengan Digital Signature (Needham-Schroeder)")
        print("  ✓ Authentication dengan signature")
        print("  ✓ Non-repudiation")
        print("  ✓ Message integrity")
        print("\nFase 2: DES tanpa Signature")
        print("  ✓ Fast symmetric encryption")
        print("  ✗ No integrity verification")
        print("  ✗ No non-repudiation")
        print("="*60)
        
        # Load keys
        self.load_keys()
        
        # Get IP addresses
        print(f"\n📍 IP Address Keyo: {self.communicator.local_ip}")
        self.other_device_ip = input("Masukkan IP Address device lain: ").strip()
        
        if not self.other_device_ip:
            print("✗ IP Address tidak boleh kosong!")
            return
        
        # Start server
        self.communicator.start_server(self.handle_incoming_message)
        print(f"✓ Terhubung dengan {self.other_device_ip}")
        print("⚠ MODE: RSA dengan signature → DES tanpa signature")
        
        # Main loop
        while not self.des_mode:
            self.show_menu()
            choice = input("Pilih: ").strip()
            
            if choice == '1' and self.handshake_stage == 0 and not self.is_initiator:
                self.send_n1_encrypted_signed()
            elif choice == '2' and not self.is_initiator and self.handshake_stage == 2:
                self.send_n1_n2_response_signed()
            elif choice == '3' and self.is_initiator and self.handshake_stage == 3:
                self.send_n2_plaintext_signed()
            elif choice == '4' and not self.is_initiator and self.handshake_stage == 4:
                self.send_secret_key_signed()
            elif choice == '9':
                print("\n🔐 Menghentikan komunikasi...")
                break
            else:
                print("Pilihan tidak valid atau tidak tersedia di stage ini")
        
        # Clean shutdown
        self.communicator.stop_server()
        print("✓ Server dihentikan")
        print("👋 Program selesai")

if __name__ == "__main__":
    device = DeviceKeyoSignature()
    device.run()
# file content end