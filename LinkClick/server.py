import socket
import threading
import tkinter as tk
from tkinter import messagebox
import os
import subprocess
import platform

HOST = '127.0.0.1'
PORT = 1234
LISTENER_LIMIT = 5
active_clients = {}
server = None
is_server_running = False

blocked_users = {}



def listen_for_messages(client, username):
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            
            if message.startswith('LOGOUT'):
                remove_client(client, username)
                break

            elif message.startswith('DOWNLOAD~'):
                filename = message.split('~')[1]
                handle_file_download(client, filename)

            elif message.startswith('NEW_FILE~'):
                # Notify about new file uploads
                add_message_to_chat_activity(message)
                
            elif message.startswith('OPEN_FILE~'):
                filename = message.split('~')[1]
                open_file(os.path.join("uploads", filename))

            elif message.startswith('PRIVATE~'):
                recipient, private_message = message[8:].split('~', 1)
                send_private_message(username, recipient, private_message)

            elif message.startswith('UPLOAD~'):
                handle_file_upload(client, message, username)

            elif message != '':
                final_msg = f"{username}~{message}"
                add_message_to_chat_activity(final_msg)
                send_message_to_all(final_msg)

            else:
                print(f"The message sent from client {username} is empty")
        except Exception as e:
            print(f"Error in message handling: {e}")
            break


uploaded_files = {}  # A dictionary to track uploaded files

def handle_file_upload(client, message, username):
    global uploaded_files
    _, filename, filesize = message.split('~')
    filesize = int(filesize)
    filepath = os.path.join("uploads", filename)

    if not os.path.exists("uploads"):
        os.makedirs("uploads")

    # Receiving the file data from the client
    with open(filepath, 'wb') as f:
        bytes_received = 0
        while bytes_received < filesize:
            data = client.recv(2048)
            if not data:
                break
            f.write(data)
            bytes_received += len(data)

    # Store the uploaded file information
    uploaded_files[filename] = (username, filesize)

    # Notify all other clients that the file is available
    notification_message = f"NEW_FILE~{username} uploaded {filename}."
    send_message_to_all(notification_message)

    # Add message to server's chat activity log
    add_message_to_chat_activity(f"[Server] {username} uploaded {filename} successfully.")
    
    # Send a command to all clients to open the file
    open_file_command = f"OPEN_FILE~{filename}"
    send_message_to_all(open_file_command)
    
def open_file(filepath):
    """Open the uploaded file using the default application."""
    try:
        if platform.system() == 'Windows':
            os.startfile(filepath)  # Windows
        elif platform.system() == 'Darwin':  # macOS
            subprocess.run(['open', filepath])
        else:  # Linux and other Unix-like systems
            subprocess.run(['xdg-open', filepath])
    except Exception as e:
        print(f"Failed to open file: {e}")


def handle_file_download(client, message):
    """Handles file download requests from clients."""
    _, filename = message.split('~')
    
    # Construct the full file path
    filepath = os.path.join("uploads", filename)
    
    # Check if the file exists in the uploads directory
    if os.path.exists(filepath):
        # Inform the client that the file is ready for download
        client.sendall(f"DOWNLOAD_READY~{filename}~{os.path.getsize(filepath)}".encode())
        
        # Create the downloads directory if it doesn't exist
        if not os.path.exists("downloads"):
            os.makedirs("downloads")
        
        # Save the file in the downloads directory
        with open(filepath, 'rb') as f:
            bytes_data = f.read(2048)
            while bytes_data:
                client.sendall(bytes_data)
                bytes_data = f.read(2048)

        # After sending the file, notify the client that the download is complete
        client.sendall("DOWNLOAD_COMPLETE".encode())
    else:
        # If the file is not found, send an error message to the client
        client.sendall("FILE_NOT_FOUND".encode())

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
    client.sendall(message.encode())

def send_message_to_all(message):
    for username, client in active_clients.items():
        send_message_to_client(client, message)

def send_private_message(sender, recipient, message):
    if recipient in active_clients:
        private_msg = f"[Private] {sender}~{message}"
        send_message_to_client(active_clients[recipient], private_msg)
        add_message_to_chat_activity(f"[Private] {sender} to {recipient}~{message}")

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