from socket import *

# Basic configurations
host: str = "0.0.0.0"  # IP
port: int = 5002  # Listening port
msg_buffer: int = 32768  # 4096 bytes
key_buffer: int = 32  # 4 bytes
vector_buffer: int = 16  # 2 bytes

# Directions as a string divided by '-'
addresses = []

# Create an address
address: tuple = (host, port)

# Create an opened socket using TCP protocol
my_socket: socket = socket(AF_INET, SOCK_STREAM)
print("Socket created!")

# Set the configurations to the socket
my_socket.bind(address)
# Set the maximum amount of listeners available
my_socket.listen(5)
print("Server ready!")

while True:
    # Get the information from the connected client
    client_connection, client_address = my_socket.accept()
    print(f"\nClient connected from: {client_address}")

    # Get the ip from the client
    addresses.append(client_address[0])

    # Send the addresses to the connected client
    client_connection.send("-".join(addresses).encode())

    # Close the client connection
    client_connection.close()
    print("Client connection closed!")

my_socket.close()
print("Server finished the process!")
