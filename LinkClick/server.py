from platform import processor
import socket
import threading
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = {}
server = None
is_server_running = False

blocked_users = {}

ENCRYPTION_KEY = b'HygT3AM_AQiSCvGwCBBIy_rdzi8AxZxL5x44CyAk7K4='
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_message(message):
    if isinstance(message, bytes):
        return cipher.encrypt(message)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message):
    if not isinstance(encrypted_message, bytes):
        encrypted_message = encrypted_message.encode()
    return cipher.decrypt(encrypted_message).decode()


def notify_logout(username, recipient):
    if recipient in active_clients:
        logout_message = f"LOGOUT_PRIVATE~{username}"
        send_message_to_client(active_clients[recipient], logout_message)

def remove_client(client, username):
    global active_clients
    client_info = client.getpeername()

    if username in active_clients:
        for user in active_clients.keys():
            if user != username:
                notify_logout(username, user)

        client.close()
        del active_clients[username]

        server_log_message = f"Client {client_info[0]}:{client_info[1]} has disconnected."
        add_message_to_server_log(server_log_message)

        prompt_message = f"Server~{username} has left the chat."
        send_message_to_all(prompt_message)
        add_message_to_chat_activity(prompt_message)
        update_connected_clients()

def listen_for_messages(client, username):
    while True:
        try:
            encrypted_message = client.recv(2048)  # Receiving encrypted message
            message = cipher.decrypt(encrypted_message).decode('utf-8')  # Decrypt message

            if message == 'LOGOUT':
                remove_client(client, username)
                break

            elif message.startswith('PRIVATE~'):
                recipient, private_message = message[8:].split('~', 1)
                send_private_message(username, recipient, private_message)

            elif message != '':
                final_msg = f"{username}~{message}"
                add_message_to_chat_activity(f"{username}: {cipher.encrypt(final_msg.encode()).decode()}")  # Log encrypted message
                send_message_to_all(final_msg)

            else:
                print(f"The message sent from client {username} is empty")
        except Exception as e:
            print(f"Error message: {e}")
            break

def send_message_to_client(client, message):
    encrypted_message = cipher.encrypt(message.encode())  # Encrypt message
    client.sendall(encrypted_message)

def send_message_to_all(message):
    if not is_server_running:
        return
    for username, client in active_clients.items():
        try:
            send_message_to_client(client, message)
        except Exception as e:
            print(f"Error sending message to {username}: {e}")

def send_private_message(sender, recipient, message):
    if recipient in active_clients:
        private_msg = f"[Private] {sender}~{message}"
        send_message_to_client(active_clients[recipient], private_msg)
        
        add_message_to_chat_activity(f"[Private] {sender} to {recipient}~{cipher.encrypt(private_msg.encode()).decode()}")

def client_handler(client):
    while True:
        try:
            username = client.recv(2048).decode('utf-8').strip()
            if username != '' and username not in active_clients:
                active_clients[username] = client
                prompt_message = f"Server~{username} added to the chat"
                add_message_to_chat_activity(prompt_message)
                send_message_to_all(prompt_message)
                update_connected_clients()
                break
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
        
        # Close all client connections
        for username, client in list(active_clients.items()):
            try:
                client.close()
            except Exception as e:
                print(f"Error closing client {username}: {e}")
        
        active_clients.clear()
        
        try:
            server.close()
            add_message_to_server_log("Server stopped.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop the server: {e}")
        finally:
            # Update connected clients box after stopping the server
            update_connected_clients()
    else:
        messagebox.showerror("Error", "Server is not running!")

def accept_clients():
    global server
    while is_server_running:
        try:
            client, address = server.accept()
            add_message_to_server_log(f"Client {address[0]}:{address[1]} connected.")
            threading.Thread(target=client_handler, args=(client,), daemon=True).start()
        except Exception as e:
            if is_server_running:
                print(f"Error accepting clients: {e}")
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
    try:
        connected_clients_box.config(state=tk.NORMAL)
        connected_clients_box.delete(1.0, tk.END)
        
        clients_list = list(active_clients.keys())
        if clients_list:
            connected_clients_box.insert(tk.END, ", ".join(clients_list))
            send_message_to_all(f"USERS~{', '.join(clients_list)}")
        else:
            connected_clients_box.insert(tk.END, "")
        
        
    except Exception as e:
        print(f"Error updating connected clients box: {e}")
    finally:
        connected_clients_box.config(state=tk.DISABLED)
    connected_clients_box.see(tk.END)


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