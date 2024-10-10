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
clients = {}

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)
print(f"Fernet Key (Share this with your clients): {key.decode()}")  # Print the key



def listen_for_messages(client, username):
    while True:
        try:
            # Receive the encrypted message
            encrypted_message = client.recv(2048)

            if encrypted_message == b'LOGOUT':
                remove_client(client, username)
                break

            # Display the encrypted message in hex format
            add_message_to_chat_activity(f"{username}: {encrypted_message.hex()}")

            # Check for special commands (PRIVATE, BLOCK, etc.) after decryption
            decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')

            if decrypted_message.startswith('PRIVATE~'):
                parts = decrypted_message.split('~', 2)
    
                if len(parts) == 3:
                    sender = parts[1]
                    encrypted_message = parts[2]
        
                    # Decrypt the message content
                    private_message = cipher.decrypt(encrypted_message.encode()).decode('utf-8')
        
                    # Send the decrypted message to the recipient
                    send_private_message(sender, username, private_message)

            # Only process regular messages, but do not show them in chat activity
            elif decrypted_message != '':
                final_msg = f"{username}~{decrypted_message}"
                send_message_to_all(final_msg)  # Still send the decrypted message to others, if needed.

            else:
                print(f"The message sent from client {username} is empty")
        except Exception as e:
            print(f"Error in message processing: {e}")
            break


def notify_logout(username, recipient):
    if recipient in active_clients:
        logout_message = f"LOGOUT_PRIVATE~{username}"
        send_message_to_client(active_clients[recipient], logout_message)  # Notify recipient only

def remove_client(client, username):
    global active_clients
    client_info = client.getpeername()

    if username in active_clients:
        # Notify private chat partners before removing the user
        for user in active_clients.keys():
            if user != username:
                notify_logout(username, user)
        
        del active_clients[username]
    client.close()

    server_log_message = f"Client {client_info[0]}:{client_info[1]} has disconnected."
    add_message_to_server_log(server_log_message)

    prompt_message = f"Server~{username} has left the chat."
    add_message_to_chat_activity(prompt_message)
    send_message_to_all(prompt_message)
    update_connected_clients()

def send_message_to_client(client, message):
     # Encrypt the message before sending it
    encrypted_message = cipher.encrypt(message.encode())
    client.sendall(encrypted_message)


def send_message_to_all(message):
    for username, client in active_clients.items():
        send_message_to_client(client, message)

def send_private_message(sender, recipient, message):
    if recipient in active_clients:
        # Encrypt only the actual message content
        encrypted_message = cipher.encrypt(message.encode())
        
        # Send the recipient info in plaintext along with the encrypted message
        private_msg = f"PRIVATE~{sender}~{encrypted_message.decode()}"
        
        send_message_to_client(active_clients[recipient], private_msg)
        add_message_to_chat_activity(f"[Private] {sender} to {recipient}: {message}")


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

        for username, client in active_clients.items():
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
        except Exception as e:
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
    connected_clients_box.config(state=tk.NORMAL)
    connected_clients_box.delete(1.0, tk.END)
    clients_list = list(active_clients.keys())
    if clients_list:
        connected_clients_box.insert(tk.END, ", ".join(clients_list))
        send_message_to_all(f"USERS~{', '.join(clients_list)}")
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