from socket import *
from threading import Thread
from tkinter import *
from tkinter import filedialog, OptionMenu
from SEncryption import SymmetricEncryption
import os

symmetricEncryption: SymmetricEncryption = SymmetricEncryption()
key: bytes = symmetricEncryption.secret_key
vector: bytes = symmetricEncryption.initialization_vector

buffer: int = 32768
addresses = [""]
clientPort: int = 6001

serverHost: str = "192.168.100.18"
serverPort: int = 5002

connections = {}


def connect_to_server(server_host, server_port):
    global addresses
    serverAddress: tuple = (server_host, server_port)

    try:
        clientSocket: socket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect(serverAddress)

        serverAnswer: bytes = clientSocket.recv(buffer)
        addresses = serverAnswer.decode().split("-")

        update_chat_box(f"IPs received: {addresses}")

        selectedIP.set(addresses[0])
        ipMenu['menu'].delete(0, 'end')

        for address in addresses:
            ipMenu['menu'].add_command(label=address, command=lambda value=address: selectedIP.set(value))

        clientSocket.close()

    except Exception as e:
        print(f"Error connecting to server: {e}")


def client_as_server():
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.bind(("0.0.0.0", clientPort))
    clientSocket.listen(5)

    update_chat_box(f"\nClient listening for P2P connections in port: {clientPort}")

    while True:
        peerSocketListen, peerAddressListen = clientSocket.accept()
        update_chat_box(f"\nP2P Client connected from {peerAddressListen[0]}")

        connections[peerAddressListen[0]] = peerSocketListen

        symmetricEncryption.secret_key = peerSocketListen.recv(32)
        symmetricEncryption.initialization_vector = peerSocketListen.recv(16)

        Thread(target=peer_connection, args=(peerSocketListen,)).start()


def peer_connection(peerSocket):
    try:
        update_ip_menu()
        peerAddress = peerSocket.getpeername()

        while True:
            messageLengthBytes = peerSocket.recv(8)
            if not messageLengthBytes:
                break
            messageLength = int.from_bytes(messageLengthBytes, byteorder='big')
            initialData = peerSocket.recv(buffer)
            if initialData.startswith(b'\x89PNG'):
                fileNameEnd = initialData.index(b'\x89PNG', 1)
                fileName = initialData[4:fileNameEnd].decode()
                remainingLength = messageLength - len(initialData)
                with open(f"received_{fileName}", "wb") as img_file:
                    img_file.write(initialData[fileNameEnd:])
                    while remainingLength > 0:
                        chunk = peerSocket.recv(min(buffer, remainingLength))
                        if not chunk:
                            break
                        img_file.write(chunk)
                        remainingLength -= len(chunk)
                update_chat_box(f"Image received: '{fileName}'")
            else:
                # It's a text message
                full_data = initialData + peerSocket.recv(messageLength - len(initialData))
                message = symmetricEncryption.symmetric_decrypt_AES_CTR(full_data).decode()
                update_chat_box(f"\nMessage received from {peerAddress[0]}: {message}")

    except Exception as e:
        print(f"Error receiving: {e}")
    finally:
        peerAddress = peerSocket.getpeername()[0]
        if peerAddress in connections:
            del connections[peerAddress]
        peerSocket.close()


def connect_to_peer():
    try:
        peerSocketSend = socket(AF_INET, SOCK_STREAM)
        peerSocketSend.connect((selectedIP.get(), clientPort))
        update_chat_box(f"\nConnected to client {selectedIP.get()}")
        peerSocketSend.send(key)
        peerSocketSend.send(vector)

        connections[selectedIP.get()] = peerSocketSend

        update_ip_menu()

        Thread(target=peer_connection, args=(peerSocketSend,)).start()

    except Exception as e:
        print(f"Error connecting to {selectedIP.get()}: {e}")


def send_message():
    message = textEntry.get()
    targetIP = selectedIP.get()

    if message == "close connection" and targetIP in connections:
        update_chat_box(f"\nConnection with {selectedIP.get()} closed!")
        connections[targetIP].close()
        del connections[targetIP]
        selectedIP.set("")
    else:
        if targetIP in connections and message:
            try:
                encryptedMessage = symmetricEncryption.symmetric_encrypt_AES_CTR(message.encode())
                messageLength = len(encryptedMessage).to_bytes(8, byteorder='big')
                print(encryptedMessage)
                connections[targetIP].send(messageLength)
                connections[targetIP].send(encryptedMessage)
                update_chat_box(f"\nSent: {message}")
            except Exception as e:
                print(f"Error sending message: {e}")
        else:
            update_chat_box(f"\nNo active connection with {targetIP}. Please connect first.")


def send_image():
    imagePath = filedialog.askopenfilename(
        title="Select an image", filetypes=[("Files PNG", "*.png"), ("Files JPEG", "*.jpg"), ("All Files", "*.*")])
    if imagePath:
        fileName = os.path.basename(imagePath)
        targetIP = selectedIP.get()
        if targetIP in connections:
            if send_image_file(connections[targetIP], imagePath):
                update_chat_box(f"Image '{fileName}' successfully sent to {targetIP}")
            else:
                update_chat_box(f"Failed to send image '{fileName}' to {targetIP}")
        else:
            update_chat_box(f"\nNo active connection with {targetIP}. Please connect first.")


def send_image_file(peer_socket, image_path):
    try:
        with open(image_path, "rb") as img_file:
            file_name = os.path.basename(image_path)
            file_size = os.path.getsize(image_path)
            header = b'\x89PNG' + file_name.encode()
            message_length = (len(header) + file_size).to_bytes(8, byteorder='big')
            peer_socket.sendall(message_length)
            peer_socket.sendall(header)
            while data := img_file.read(buffer):
                peer_socket.sendall(data)
    except Exception as e:
        print(f"Error sending image: {e}")


def update_chat_box(message):
    chatBox.config(state=NORMAL)
    chatBox.insert(END, message + "\n")
    chatBox.config(state=DISABLED)


def update_ip_menu():
    ipMenu['menu'].delete(0, 'end')
    for address in connections.keys():
        ipMenu['menu'].add_command(label=address, command=lambda value=address: selectedIP.set(value))


def start_connection_server():
    server_host = ipEntry.get() or serverHost
    server_port = portEntry.get() or serverPort
    server_port = int(server_port)
    connect_to_server(server_host, server_port)
    Thread(target=client_as_server, daemon=True).start()


app = Tk()
app.title("Cliente 1")
app.geometry("375x800")

selectedIP = StringVar(app)
selectedIP.set(addresses[0])

Label(app, text="Server IP:").grid(row=0, column=0, padx=5)
ipEntry = Entry(app)
ipEntry.insert(0, serverHost)
ipEntry.grid(row=1, column=0, padx=5)

Label(app, text="Server Port:").grid(row=2, column=0, padx=5)
portEntry = Entry(app)
portEntry.insert(0, str(serverPort))
portEntry.grid(row=3, column=0, padx=5)

connectServerButton = Button(app, text="Connect to Server", command=start_connection_server)
connectServerButton.grid(row=2, column=1, padx=5)

Label(app).grid(row=4, column=0, padx=5)

Label(app, text="Client IPs:").grid(row=5, column=0, padx=5)
ipMenu = OptionMenu(app, selectedIP, *addresses)
ipMenu.grid(row=6, column=0, padx=5)

Label(app).grid(row=7, column=0)

connectClientButton = Button(app, text="Connect to Client", command=connect_to_peer)
connectClientButton.grid(row=6, column=1, padx=5)

Label(app, text="Text input:").grid(row=8, column=0, columnspan=2, padx=5)
textEntry = Entry(app, width=38)
textEntry.grid(row=9, column=0, columnspan=2, padx=5)

sendTextButton = Button(app, text="Send Text", width=7, command=send_message)
sendTextButton.grid(row=10, column=0, columnspan=2, padx=5)

sendImageButton = Button(app, text="Send Image", width=7, command=send_image)
sendImageButton.grid(row=11, column=0, columnspan=2, padx=5)

Label(app).grid(row=12, column=0, padx=5)

chatBox = Text(app, state=DISABLED, height=100, width=50)
chatBox.grid(row=13, column=0, columnspan=2, padx=5)

app.mainloop()
