import socket
import threading
import sqlite3
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Database initialization function
def init_db():
    conn = sqlite3.connect('honeypot.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT,
                        ip_address TEXT,
                        data TEXT)''')
    conn.commit()
    conn.close()

# Function to log interaction to the database
def log_to_db(service, ip, data, conn):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (service, ip_address, data) VALUES (?, ?, ?)", (service, ip, data))
    conn.commit()

# Handle SSH interactions
def handle_ssh(client_socket, client_address):
    conn = sqlite3.connect('honeypot.db')
    """Handle SSH connections, prompt for username and password, and log credentials."""
    client_socket.sendall(b"Welcome to the SSH honeypot!\n")
   
    # Request for username
    client_socket.sendall(b"Username: ")
    username = client_socket.recv(1024).decode('utf-8').strip()
   
    # Request for password
    client_socket.sendall(b"Password: ")
    password = client_socket.recv(1024).decode('utf-8').strip()
   
    # Log the credentials to the database
    log_credentials_to_db('SSH', client_address[0], username, password,conn)
   
    # Respond to the attacker
    client_socket.sendall(b"Authentication failed.\n")
    client_socket.close()


def log_credentials_to_db(protocol, ip, username, password, conn):
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS credentials (protocol TEXT, ip TEXT, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO credentials (protocol, ip, username, password) VALUES (?, ?, ?, ?)",
                   (protocol, ip, username, password))
    conn.commit()
# Handle HTTP interactions
def handle_http(client_socket, client_address):
    conn = sqlite3.connect('honeypot.db')  # New connection in this thread
    try:
        request = client_socket.recv(1024).decode('utf-8')
        log_to_db('HTTP', client_address[0], request, conn)
        response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><h1>It works!</h1></body></html>"
        client_socket.send(response.encode('utf-8'))
    except UnicodeDecodeError:
        request = "<binary data or invalid encoding>"
        log_to_db('HTTP', client_address[0], request, conn)
    except BrokenPipeError:
        logging.warning(f"[!] Broken pipe error while handling HTTP request from {client_address}")
    finally:
        client_socket.close()
        conn.close()

# Handle FTP interactions
def handle_ftp(client_socket, client_address):
    conn = sqlite3.connect('honeypot.db')  # New connection in this thread
    try:
        # Send fake FTP server banner
        client_socket.send(b"220 FakeFTP_1.0 Server Ready\r\n")
       
        # Receive and log the username
        request = client_socket.recv(1024).decode('utf-8')
        if request.startswith("USER"):
            username = request.split(" ")[1].strip()
            log_to_db('FTP', client_address[0], f"Username: {username}", conn)
            client_socket.send(b"331 Username okay, need password.\r\n")
       
        # Receive and log the password
        request = client_socket.recv(1024).decode('utf-8')
        if request.startswith("PASS"):
            password = request.split(" ")[1].strip()
            log_to_db('FTP', client_address[0], f"Password: {password}", conn)
            client_socket.send(b"530 Not logged in.\r\n")  # Simulate failed login
       
    except UnicodeDecodeError:
        log_to_db('FTP', client_address[0], "<binary data or invalid encoding>", conn)
    except BrokenPipeError:
        logging.warning(f"[!] Broken pipe error while handling FTP request from {client_address}")
    finally:
        client_socket.close()
        conn.close()
# Function to run each service
def run_service(service_name, ip, port, handler):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(5)
    logging.info(f"Started {service_name} service on port {port}")
   
    while True:
        client_socket, client_address = server.accept()
        logging.info(f"Accepted connection from {client_address} on {service_name}")
        thread = threading.Thread(target=handler, args=(client_socket, client_address))
        thread.start()

# Main function to start the honeypot services
def start_honeypot():
    init_db()

    # Define the IP and ports
    ip = '0.0.0.0'
   
    # Start the SSH, HTTP, and FTP services
    ssh_thread = threading.Thread(target=run_service, args=('SSH', ip, 2222, handle_ssh))
    http_thread = threading.Thread(target=run_service, args=('HTTP', ip, 80, handle_http))
    ftp_thread = threading.Thread(target=run_service, args=('FTP', ip, 21, handle_ftp))

    ssh_thread.start()
    http_thread.start()
    ftp_thread.start()

# Run the honeypot
if __name__ == "__main__":
    start_honeypot()
