# file name: http_handler.py
# file content begin
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.request
import socket
import threading
import time
import random

def get_local_ip():
    """Mendapatkan IP address lokal"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def generate_nonce():
    """Generate unique nonce untuk setiap request"""
    return random.randint(1, 2**31)

class MessageRequestHandler(BaseHTTPRequestHandler):
    """Handler untuk menerima HTTP POST request"""
    
    message_callback = None
    
    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Tambahkan timestamp penerimaan
            data['received_at'] = time.time()
            
            print(f"✓ Pesan diterima: {data.get('type', 'unknown')}")
            
            # Callback untuk memproses pesan yang diterima
            if MessageRequestHandler.message_callback:
                response_data = MessageRequestHandler.message_callback(data)
            else:
                response_data = {'status': 'received'}
            
            # Tambahkan timestamp ke response
            response_data['response_timestamp'] = int(time.time())
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
            
        except Exception as e:
            print(f"Error handling POST request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging untuk mengurangi clutter
        pass

class HTTPCommunicator:
    """Class untuk menangani komunikasi HTTP dengan timestamp support"""
    
    def __init__(self, port=8080):
        self.port = port
        self.local_ip = get_local_ip()
        self.server = None
        self.server_thread = None
        self.is_running = False
        
    def start_server(self, callback):
        """Memulai HTTP server"""
        MessageRequestHandler.message_callback = callback
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), MessageRequestHandler)
            self.is_running = True
            self.server_thread = threading.Thread(target=self._serve_forever, daemon=True)
            self.server_thread.start()
            print(f"✓ Server berjalan di {self.local_ip}:{self.port}")
        except Exception as e:
            print(f"✗ Gagal memulai server: {e}")
    
    def _serve_forever(self):
        """Serve forever"""
        while self.is_running:
            try:
                self.server.handle_request()
            except Exception as e:
                if self.is_running:  # Only log if we're supposed to be running
                    pass
    
    def send_message(self, target_ip, data):
        """Mengirim pesan ke device lain"""
        url = f'http://{target_ip}:{self.port}'
        headers = {'Content-Type': 'application/json'}
        
        # Tambahkan timestamp dan nonce jika belum ada
        if 'timestamp' not in data:
            data['timestamp'] = int(time.time())
        
        if 'nonce' not in data:
            data['nonce'] = generate_nonce()
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, json.dumps(data).encode('utf-8'), headers)
                response = urllib.request.urlopen(req, timeout=30)  # Increased timeout
                response_data = json.loads(response.read().decode('utf-8'))
                print(f"✓ Pesan berhasil dikirim ke {target_ip}")
                return response_data
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"⚠ Percobaan {attempt + 1} gagal, mencoba lagi...")
                    time.sleep(2)
                else:
                    raise Exception(f"Gagal mengirim pesan ke {target_ip} setelah {max_retries} percobaan: {e}")
    
    def stop_server(self):
        """Menghentikan server"""
        self.is_running = False
        if self.server:
            self.server.shutdown()

# ============= TAMBAHAN: Validator untuk mencegah replay attacks =============

class RequestValidator:
    """Class untuk memvalidasi request dan mencegah replay attacks (opsional)"""
    
    def __init__(self, window_seconds=300):
        self.window_seconds = window_seconds  # 5 menit
        self.seen_nonces = set()
    
    def validate_request(self, data):
        """Validasi request untuk mencegah replay attacks"""
        validation_errors = []
        
        # Validasi timestamp
        if 'timestamp' in data:
            try:
                request_time = int(data['timestamp'])
                current_time = int(time.time())
                
                # Cek apakah timestamp dalam window yang diizinkan
                if abs(current_time - request_time) > self.window_seconds:
                    validation_errors.append(f"Timestamp expired (request: {request_time}, current: {current_time})")
            except:
                validation_errors.append("Invalid timestamp format")
        
        # Validasi nonce
        if 'nonce' in data:
            nonce = data['nonce']
            if nonce in self.seen_nonces:
                validation_errors.append(f"Nonce {nonce} already used")
            else:
                self.seen_nonces.add(nonce)
                
                # Bersihkan nonce lama (opsional, untuk mencegah memory leak)
                if len(self.seen_nonces) > 1000:
                    # Keep only recent 1000 nonces
                    self.seen_nonces = set(list(self.seen_nonces)[-1000:])
        
        return len(validation_errors) == 0, validation_errors

# Buat instance validator global (bisa digunakan di kedua device)
validator = RequestValidator()

# ============= TAMBAHAN: Fungsi helper untuk signature-based communication =============

def create_signed_request(sender, message_type, content, timestamp=None, nonce=None):
    """Membuat request dengan metadata untuk signature-based communication"""
    if timestamp is None:
        timestamp = int(time.time())
    
    if nonce is None:
        nonce = generate_nonce()
    
    request = {
        'type': message_type,
        'sender': sender,
        'timestamp': timestamp,
        'nonce': nonce,
        **content  # Gabungkan dengan konten pesan
    }
    
    return request

def validate_signed_response(response, expected_type=None):
    """Validasi response dari signed communication"""
    if not response:
        return False, "Empty response"
    
    if 'response_timestamp' not in response:
        return False, "No timestamp in response"
    
    if expected_type and response.get('type') != expected_type:
        return False, f"Unexpected response type: {response.get('type')}"
    
    return True, "Response valid"
# file content end