import argparse
import socket
import signal
import sys
import threading
from protocol.messages import *
from utils.rsa import *
from utils.netaddr import *
from colorama import init, Fore

init()

message_receiver: bool = False  # Flag indicating whether the server is actively receiving messages
connections = {}  # Dictionary to store the connections with clients
last_communication_address = tuple[str, int]  # Variable to store the last communication address
using_encrypted_channel: bool = False  # Flag indicating whether the communication channel should be encrypted
encryption_key: tuple[bytes, bytes]  # Variable to store the encryption key
private_key: bytes  # Variable to store the server's private key
public_key: bytes  # Variable to store the server's public key

def signal_handler(sig, frame):
    # Signal handler function for SIGINT (Ctrl+C)
    global message_receiver
    print('###: Disconnecting ...')
    message_receiver = False  # Set the message_receiver flag to False to stop receiving messages
    print('###: Disconnected.')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Argument Parsing
parser = argparse.ArgumentParser(description='Run server.py with specified port number')
parser.add_argument('-p', '--port', type=int, help='Port number to listen on', required=True)
parser.add_argument('-i', '--ip', type=str, help='IP address to serve on', required=True)
parser.add_argument('-e', '--encrypted', action='store_true', help='Enables encrypted communication channel.')
parser.add_argument('-u', '--user', type=str, help='Username that owns RSA key-pairs.')

args = parser.parse_args()

def check_address_availability(ip_address: str, port: int):
    # Check if the specified IP address and port are available
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(10)
        result = socket_connection.bind((ip_address, port))
        socket_connection.close()
        return True
    except:
        return False

def receive_messages(socket_connection: socket.socket, buffer_size: int = 1024):
    # Function to receive messages from clients
    global message_receiver, connections, using_encrypted_channel, private_key
    while message_receiver:
        try:
            message = socket_connection.recv(buffer_size)
            sender_addr = socket_connection.getpeername()
            proto_message = is_proto_message(message)
            if not proto_message:  # Check if it's a protocol message or not
                if using_encrypted_channel:  # Check if encryption is enabled
                    message = decrypt(message, private_key).decode('utf-8')  # Decrypt the message
                else:
                    message = message.decode('utf-8')  # Decode the message
                if message and len(message) > 0:
                    print(f"\r{Fore.LIGHTBLUE_EX}{sender_addr[0]}:{sender_addr[1]}:{Fore.RESET} {message}\n#: ", end='')
            else:
                if proto_message == PROTOCOL_MESSAGES.CON_SYN.name:
                    # Handle connection synchronization message
                    socket_connection.shutdown(2)
                    socket_connection.close()
                    connections.pop(localaddr_from_netaddr(socket_connection.getpeername()))  # Remove the connection from the dictionary
        except:
            pass
    socket_connection.close()

def send_message(relay_ip: str, relay_port: int | None, message: str):
    # Function to send messages to clients
    global connections, last_communication_address, using_encrypted_channel
    if message and len(message) > 0:
        if relay_ip is not None and relay_port is not None:
            socket_address = (relay_ip, relay_port)
        else:
            socket_address = last_communication_address

        connection_db = connections[localaddr_from_netaddr(socket_address)]
        socket_connection: socket.socket = connection_db['socket']

        if using_encrypted_channel:  # Check if encryption is enabled
            relay_public_key: bytes = connection_db['public_key']
            encrypted_message = encrypt(message.encode(), relay_public_key)  # Encrypt the message
            socket_connection.send(encrypted_message)
        else:
            socket_connection.send(message.encode())

def exhange_public_keys(socket_connection: socket.socket) -> None:
    # Function to exchange public keys with a client for encryption
    global public_key, connections
    socket_connection.send(public_key)  # Send the server's public key to the client
    relay_public_key = socket_connection.recv(4096)  # Receive the client's public key
    socket_address = socket_connection.getpeername()
    connections[localaddr_from_netaddr(socket_address)]['public_key'] = relay_public_key
    print(f"###: Key exchange was successful with {socket_address[0]}:{socket_address[1]}")

def new_connection_handler(socket_connection: socket.socket):
    # Function to handle a new connection with a client
    global using_encrypted_channel, connections
    if using_encrypted_channel:  # Check if encryption is enabled
        socket_connection.send(PROTOCOL_MESSAGES.CON_ENC.value)  # Send the encryption protocol message to the client
        protocol_encryption_answer = socket_connection.recv(8)  # Receive the encryption protocol response from the client
        if protocol_encryption_answer == PROTOCOL_MESSAGES.CON_ENC_OK.value:
            exhange_public_keys(socket_connection)  # Exchange public keys with the client for encryption
            send_message(*socket_connection.getpeername(), message='###: You are connected to server now!\nAll the messages are E2EE.')
            message_receiver_thread = threading.Thread(target=receive_messages, args=(socket_connection,))
            message_receiver_thread.start()  # Start the message receiver thread
        elif protocol_encryption_answer == PROTOCOL_MESSAGES.CON_ENC_NOK.value:
            connection_error = '\rSERVER: Failed to connect!\n'
            connection_error += 'Detail: Server only accepts connections who use encryption channels for communications. Use -e flag to start an encrypted communication channel or connect to another server.'
            socket_connection.send(connection_error.encode())
            connections.pop(localaddr_from_netaddr(socket_connection.getpeername()))  # Remove the connection from the dictionary
            socket_connection.shutdown(2)
            socket_connection.close()
    else:
        socket_connection.send('###: You are connected to server now!'.encode())
        message_receiver_thread = threading.Thread(target=receive_messages, args=(socket_connection,))
        message_receiver_thread.start()  # Start the message receiver thread

def setup_multi_connections(socket_connection: socket.socket):
    # Function to setup multiple connections with clients
    global message_receiver, connections, last_communication_address
    while message_receiver:
        new_connection, new_connection_address = socket_connection.accept()  # Accept a new connection
        if new_connection_address is not None and type(new_connection_address) == tuple and len(new_connection_address) > 0:
            connections[localaddr_from_netaddr(new_connection_address)] = {
                'socket': new_connection,
                'public_key': None
            }
            if len(connections) == 1:
                last_communication_address = new_connection_address  # Update the last communication address
            new_connection_handler(new_connection)

def generate_rsa_keys(user: str) -> None:
    # Generate RSA key pairs for encryption
    global private_key, public_key
    private_key, public_key = generate_rsa_key_pair(user)

def parse_relay_query(relay_query: str) -> tuple[str, int, str] | None:
    # Parse the relay query into relay IP, port, and message
    global last_communication_address
    relay_query_separated = relay_query.split(':')
    try:
        if len(relay_query_separated) == 1 and last_communication_address is not None:
            relay_ip, relay_port = last_communication_address
            return (relay_ip, relay_port, relay_query_separated[0])
        else:
            relay_ip = relay_query_separated[0]
            relay_port = int(relay_query_separated[1])
            relay_message = relay_query_separated[2]
            return (relay_ip, relay_port, relay_message)
    except:
        return None

def run() -> None:
    # Main function to run the server
    global message_receiver, connections, last_communication_address, using_encrypted_channel
    ip_address = args.ip
    port_number = args.port
    using_encrypted_channel = args.encrypted
    user = ""
    if using_encrypted_channel:
        if args.user is not None:
            user = args.user
            generate_rsa_keys(user)  # Generate RSA key pairs for encryption
        else:
            print(f"###: Error: You need to specify a username when using encrypted communication channels.")
            exit()
    server_address = (ip_address, port_number)

    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"###: Binding on {ip_address}:{port_number}")
    if check_address_availability(*server_address):
        try:
            socket_connection.bind(server_address)
            socket_connection.listen(5)
            print("###: Binded!")
            message_receiver = True
            multi_connection_thread = threading.Thread(target=setup_multi_connections, args=(socket_connection,))
            multi_connection_thread.start()  # Start the multi-connection thread

            while True:
                if len(connections) > 0:
                    parsed_relay_query = parse_relay_query(input("#: "))
                    if parsed_relay_query is not None:
                        last_communication_address = (parsed_relay_query[0], parsed_relay_query[1])  # Update the last communication address
                        send_message(*parsed_relay_query)  # Send the relay message
        except:
            print(f"###: Error: There was a connection error.")
    else:
        print(f"###: Error: Failed to bind on '{ip_address}:{port_number}'")

if __name__ == "__main__":
    run()
