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
            if message == 'LOGOUT':
                remove_client(client, username)
                break
            if message != '':
                final_msg = f"{username}~{message}"
                add_message_to_chat_activity(final_msg)
                send_message_to_all(final_msg)
            else:
                print(f"The message sent from client {username} is empty")
        except:
            break

def remove_client(client, username):
    global active_clients
    for u, c in active_clients:
        if c == client:
            active_clients.remove((u, c))
            break
    client.close()
    prompt_message = f"Server~{username} has left the chat."
    add_message_to_chat_activity(prompt_message)
    add_message_to_server_log(prompt_message)
    send_message_to_all(prompt_message)
    update_connected_clients()

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
                prompt_message = f"Server~{username} added to the chat"
                add_message_to_chat_activity(prompt_message)
                add_message_to_server_log(prompt_message)
                send_message_to_all(prompt_message)
                update_connected_clients()
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
            add_message_to_server_log(f"Server started on {HOST} {PORT}")
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
            add_message_to_server_log("Server stopped.")
            update_connected_clients()
        except:
            messagebox.showerror("Error", "Failed to stop the server.")
    else:
        messagebox.showerror("Error", "Server is not running!")

def accept_clients():
    global server
    while is_server_running:
        try:
            client, address = server.accept()
            add_message_to_server_log(f"Client {address[0]}:{address[1]} connected.")
            threading.Thread(target=client_handler, args=(client,), daemon=True).start()
        except:
            break

def add_message_to_server_log(message):
    server_log_box.config(state=tk.NORMAL)
    server_log_box.insert(tk.END, message + '\n')
    server_log_box.see(tk.END)
    server_log_box.config(state=tk.DISABLED)

def add_message_to_chat_activity(message):
    chat_activity_box.config(state=tk.NORMAL)
    chat_activity_box.insert(tk.END, message + '\n')
    chat_activity_box.see(tk.END)
    chat_activity_box.config(state=tk.DISABLED)

def update_connected_clients():
    connected_clients_box.config(state=tk.NORMAL)
    connected_clients_box.delete(1.0, tk.END)
    if active_clients:
        for username, client in active_clients:
            connected_clients_box.insert(tk.END, f"{username}, ")
    else:
        connected_clients_box.insert(tk.END, "")
    connected_clients_box.see(tk.END)
    connected_clients_box.config(state=tk.DISABLED)

# GUI
root = tk.Tk()
root.geometry("600x750")
root.title("Server Control")
root.resizable(False, False)

server_log_label = tk.Label(root, text="Server Log:", font=("Helvetica", 14))
server_log_label.pack(pady=5)
server_log_box = tk.Text(root, height=10, state=tk.DISABLED)
server_log_box.pack(pady=10, padx=10)

chat_activity_label = tk.Label(root, text="Chat Activity:", font=("Helvetica", 14))
chat_activity_label.pack(pady=5)
chat_activity_box = tk.Text(root, height=10, state=tk.DISABLED)
chat_activity_box.pack(pady=10, padx=10)


connected_clients_label = tk.Label(root, text="Connected Clients:", font=("Helvetica", 14))
connected_clients_label.pack(pady=5)
connected_clients_box = tk.Text(root, height=5, state=tk.DISABLED)
connected_clients_box.pack(pady=5, padx=10)

start_button = tk.Button(root, text="Start Server", font=("Helvetica", 15), bg='#464EB8', fg='white', command=start_server)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Server", font=("Helvetica", 15), bg='#FF6347', fg='white', command=stop_server)
stop_button.pack(pady=5)

def main():
    root.mainloop()

if __name__ == "__main__":
    main()
