from socket import *
from threading import Thread
from tkinter import *
from tkinter import messagebox, filedialog, OptionMenu
from SEncryption import SymmetricEncryption
import os

symmetric_en: SymmetricEncryption = SymmetricEncryption()
key: bytes = symmetric_en.secret_key
vector: bytes = symmetric_en.initialization_vector

buffer: int = 32768
addresses = [""]
clientPort: int = 6001

serverHost: str = "192.168.100.18"
serverPort: int = 5002

peerSocketSend: socket
peerSocketListen: socket

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
    global peerSocketListen

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.bind(("0.0.0.0", clientPort))
    clientSocket.listen(5)

    update_chat_box(f"\nClient listening for P2P connections in port: {clientPort}")

    while True:
        peerSocketListen, peerAddressListen = clientSocket.accept()
        update_chat_box(f"\nP2P Client connected from {peerAddressListen[0]}")

        connections[peerAddressListen[0]] = peerSocketListen

        Thread(target=peer_connection, args=(peerSocketListen,)).start()


def peer_connection(peerSocket):
    try:
        update_ip_menu()
        peerAddress = peerSocket.getpeername()
        while True:
            data = peerSocket.recv(buffer)
            if not data:
                break

            if data[:4] == b'IMG:':
                file_name = data[4:].decode()
                receive_image(peerSocket, file_name)
            else:
                message = data.decode()
                update_chat_box(f"\nMessage received from {peerAddress[0]}: {message}")

    except Exception as e:
        print(f"Error receiving: {e}")
    finally:
        peerAddress = peerSocket.getpeername()[0]
        if peerAddress in connections:
            del connections[peerAddress]
        peerSocket.close()


def connect_to_peer():
    global peerSocketSend

    try:
        peerSocketSend = socket(AF_INET, SOCK_STREAM)
        peerSocketSend.connect((selectedIP.get(), clientPort))
        update_chat_box(f"\nConnected to client {selectedIP.get()}")
        peerSocketSend.send("Hi from client 1!".encode())

        connections[selectedIP.get()] = peerSocketSend

        update_ip_menu()

        Thread(target=peer_connection, args=(peerSocketSend,)).start()

    except Exception as e:
        print(f"Error connecting to {selectedIP.get()}: {e}")


def send_message():
    global peerSocketSend

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
                connections[targetIP].send(message.encode())
                update_chat_box(f"\nSent: {message}")
            except Exception as e:
                print(f"Error sending message: {e}")
        else:
            update_chat_box(f"\nNo active connection with {targetIP}. Please connect first.")


def send_image():
    global addresses
    image_path = filedialog.askopenfilename(title="Select and image",
                                            filetypes=[("Files PNG", "*.png"), ("Files JPEG", "*.jpg"),
                                                       ("All Files", "*.*")])
    if image_path:
        try:
            file_name = os.path.basename(image_path)

            for i in range(1, len(addresses)):
                try:
                    peer_socket = socket(AF_INET, SOCK_STREAM)
                    peer_socket.connect((addresses[i], clientPort))
                    update_chat_box(f"Sending image '{file_name}' to {addresses[i]}")

                    peer_socket.send(f"IMG:{file_name}".encode())
                    send_image_file(peer_socket, image_path)

                    peer_socket.close()
                except Exception as e:
                    update_chat_box(f"Error al enviar imagen a {addresses[i]}: {e}")
        except Exception as e:
            update_chat_box(f"Error seleccionando imagen: {e}")


def send_image_file(peer_socket, image_path):
    with open(image_path, "rb") as img_file:
        while data := img_file.read(buffer):
            peer_socket.sendall(data)


def receive_image(peer_socket, file_name):
    with open(f"received_{file_name}", "wb") as img_file:
        while data := peer_socket.recv(buffer):
            if not data:
                break
            img_file.write(data)

    update_chat_box(f"Image received: '{file_name}'")


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
app.geometry("380x800")

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
