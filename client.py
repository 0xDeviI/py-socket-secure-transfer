import argparse
import socket
import signal
import sys
import threading
from colorama import init, Fore
from protocol.messages import *
from utils.rsa import *

init()

# Global Variables
message_receiver: bool = False  # Flag indicating whether the client is actively receiving messages
using_encrypted_channel: bool = False  # Flag indicating whether the communication channel should be encrypted
server_public_key: bytes  # Variable to store the server's public key
private_key: bytes  # Variable to store the client's private key
public_key: bytes  # Variable to store the client's public key

def signal_handler(sig, frame):
    # Signal handler function for SIGINT (Ctrl+C)
    global message_receiver
    print('###: Disconnecting ...')
    message_receiver = False  # Set the message_receiver flag to False to stop receiving messages
    print('###: Disconnected.')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Argument Parsing
parser = argparse.ArgumentParser(description='Run client.py with specified port number')
parser.add_argument('-p', '--port', type=int, help='Port number to listen on', required=True)
parser.add_argument('-i', '--ip', type=str, help='IP address to serve on', required=True)
parser.add_argument('-e', '--encrypted', action='store_true', help='Enables encrypted communication channel.')
parser.add_argument('-u', '--user', type=str, help='Username that owns RSA key-pairs.')

args = parser.parse_args()

def check_address_availability(ip_address: str, port: int):
    # Check if the specified IP address and port are available
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_connection:
            socket_connection.settimeout(3)
            result = socket_connection.connect_ex((ip_address, port))
            if result == 0:
                socket_connection.send(PROTOCOL_MESSAGES.CON_SYN.value)
                socket_connection.close()
                return True
            else:
                return False
    except (socket.error, socket.timeout):
        return False

def receive_messages(socket_connection: socket.socket, buffer_size: int = 1024):
    # Function to receive messages from the server
    global message_receiver, using_encrypted_channel, server_public_key, public_key, private_key
    while message_receiver:  # Loop while message_receiver flag is True
        try:
            message = socket_connection.recv(buffer_size)
            proto_message = is_proto_message(message)
            if not proto_message:  # Check if it's a protocol message or not
                if using_encrypted_channel:  # Check if encryption is enabled
                    message = decrypt(message, private_key).decode('utf-8')  # Decrypt the message
                else:
                    message = message.decode('utf-8')  # Decode the message
                if message and len(message) > 0:
                    print(f"{Fore.LIGHTBLUE_EX}Received:{Fore.RESET} {message}")  # Print the received message
            else:
                if proto_message == PROTOCOL_MESSAGES.CON_SYN.name:
                    # Handle connection synchronization message
                    socket_connection.shutdown(2)
                    socket_connection.close()
                elif proto_message == PROTOCOL_MESSAGES.CON_ENC.name:
                    # Handle connection encryption message
                    if using_encrypted_channel:
                        socket_connection.send(PROTOCOL_MESSAGES.CON_ENC_OK.value)
                        server_public_key = socket_connection.recv(4096)
                        socket_connection.send(public_key)
                    else:
                        socket_connection.send(PROTOCOL_MESSAGES.CON_ENC_NOK.value)
        except:
            pass
    socket_connection.close()

def send_message(socket_connection: socket.socket, message: str):
    # Function to send messages to the server
    global server_public_key, using_encrypted_channel
    if message and len(message) > 0:
        if using_encrypted_channel:  # Check if encryption is enabled
            encrypted_message = encrypt(message.encode(), server_public_key)  # Encrypt the message
            socket_connection.send(encrypted_message)
        else:
            socket_connection.send(message.encode())

def generate_rsa_keys(user: str) -> None:
    # Generate RSA key pairs for encryption
    global private_key, public_key
    private_key, public_key = generate_rsa_key_pair(user)

def run() -> None:
    # Main execution function
    global message_receiver, using_encrypted_channel
    ip_address = args.ip
    port_number = args.port
    server_address = (ip_address, port_number)

    using_encrypted_channel = args.encrypted
    user = ""
    if using_encrypted_channel:
        if args.user:
            user = args.user
            generate_rsa_keys(user)  # Generate RSA key pairs
        else:
            print(f"###: Error: You need to specify a username when using encrypted communication channels.")
            exit()

    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"###: Connecting to {ip_address}:{port_number}")
    if check_address_availability(*server_address):  # Check if the address is available
        try:
            socket_connection.connect(server_address)
            print("###: Connected!")
            message_receiver = True  # Set message_receiver flag to True to start receiving messages
            message_receiver_thread = threading.Thread(target=receive_messages, args=(socket_connection,))
            message_receiver_thread.start()  # Start the message receiver thread
            while True:
                message = input()
                send_message(socket_connection, message)
        except:
            print(f"###: Error: There was an error connecting.")
    else:
        print(f"###: Error: Failed to bind on '{ip_address}:{port_number}'")

if __name__ == "__main__":
    run()  # Start the main execution function
