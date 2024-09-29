#Server.py
import socket
import threading
import tkinter as tk
from tkinter import messagebox

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = []
server = None
is_server_running = False

def listen_for_messages(client, username):
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            if message != '':
                final_msg = username + '~' + message
                send_message_to_all(final_msg)
            else:
                print(f"The message sent from client {username} is empty")
        except:
            break

def send_message_to_client(client, message):
    client.sendall(message.encode())

def send_message_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)

def client_handler(client):
    while True:
        try:
            username = client.recv(2048).decode('utf-8')
            if username != '':
                active_clients.append((username, client))
                prompt_message = "SERVER~" + f"{username} added to the chat"
                send_message_to_all(prompt_message)
                break
            else:
                print("Client username is empty")
        except:
            break

    threading.Thread(target=listen_for_messages, args=(client, username)).start()

def start_server():
    global server, is_server_running

    if not is_server_running:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((HOST, PORT))
            print(f"Running the server on {HOST} {PORT}")
            add_message(f"Server started on {HOST} {PORT}")
        except:
            messagebox.showerror("Error", f"Unable to bind host {HOST} and port {PORT}")
            return

        server.listen(LISTENER_LIMIT)
        is_server_running = True

        threading.Thread(target=accept_clients, daemon=True).start()

def stop_server():
    global server, is_server_running
    if is_server_running:
        is_server_running = False

        for username, client in active_clients:
            try:
                client.close() 
            except:
                pass

        active_clients.clear()  

        try:
            server.close()
            add_message("Server stopped.")
        except:
            messagebox.showerror("Error", "Failed to stop the server.")
    else:
        messagebox.showerror("Error", "Server is not running!")


def accept_clients():
    global server
    while is_server_running:
        try:
            client, address = server.accept()
            add_message(f"Client {address[0]}:{address[1]} connected.")
            threading.Thread(target=client_handler, args=(client,), daemon=True).start()
        except:
            break

def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)

root = tk.Tk()
root.geometry("400x400")
root.title("Server Control")
root.resizable(False, False)

message_box = tk.Text(root, height=15, state=tk.DISABLED)
message_box.pack(pady=20)

start_button = tk.Button(root, text="Start Server", font=("Helvetica", 15) ,bg='#464EB8', fg='white', command=start_server)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Server", font=("Helvetica", 15), bg='#464EB8', fg='white', command=stop_server)
stop_button.pack(pady=5)

def main():
    root.mainloop()

if __name__ == "__main__":
    main()
