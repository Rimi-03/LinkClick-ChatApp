import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, Listbox, Scrollbar
from cryptography.fernet import Fernet


HOST = '127.0.0.1'
PORT = 1234

DARK_GREY = '#2E2E2E'
LIGHT_GREY = '#D3D3D3'
OCEAN_BLUE = '#5DADE2'
SOFT_WHITE = '#F4F6F7'
WHITE = "white"
FONT = ("Helvetica", 13, "bold")
BUTTON_FONT = ("Helvetica", 13, "bold")
SMALL_FONT = ("Helvetica", 11)
HEADER_FONT = ("Helvetica", 16, "bold")
RED = "#FF0000"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
is_connected = False

# Dictionary to store private chat windows
private_chat_windows = {}
blocked_users = set()

ENCRYPTION_KEY = b'HygT3AM_AQiSCvGwCBBIy_rdzi8AxZxL5x44CyAk7K4='
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_message(message):
    if isinstance(message, bytes):  # If message is already bytes, avoid re-encoding
        return cipher.encrypt(message)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message):
    if not isinstance(encrypted_message, bytes):  # Ensure it's bytes before decrypting
        encrypted_message = encrypted_message.encode()
    return cipher.decrypt(encrypted_message).decode()


def add_message(message):
    message_box.config(state=tk.NORMAL)

    if "[Error]" in message or "[Server]" in message:
        message_box.insert(tk.END, message + '\n', 'error')
    else:
        message_box.insert(tk.END, message + '\n')

    message_box.config(state=tk.DISABLED)
    message_box.see(tk.END)

def update_online_clients(clients_list):
    online_users_box.config(state=tk.NORMAL)
    online_users_box.delete(1.0, tk.END)
    for client in clients_list:
        online_users_box.insert(tk.END, f"->{client}\n")
    online_users_box.config(state=tk.DISABLED)

def connect():
    global client, is_connected, HOST, PORT
    HOST = host_textbox.get().strip()
    PORT = int(port_textbox.get().strip())
    username = username_textbox.get().strip()

    if username == "":
        messagebox.showerror("Invalid username", "Username cannot be empty!")
        username_textbox.focus_set()
        return
    
    if is_connected:
        add_message("[Client] Already connected to the server.")
        return

    try:
        client.connect((HOST, PORT))
        add_message("[Server] Connected")
        is_connected = True
    except:
        add_message(f"[Error] Connection to server {HOST}:{PORT} failed.")
        return
    
    client.sendall(username.encode())
    threading.Thread(target=listen_for_messages_from_server, args=(client,), daemon=True).start()

    host_textbox.config(state=tk.DISABLED)
    port_textbox.config(state=tk.DISABLED)
    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)
    message_button.config(state=tk.NORMAL)
    reconnect_button.config(state=tk.NORMAL)
    logout_button.config(state=tk.NORMAL)
    private_chat_button.config(state=tk.NORMAL)


def reconnect():
    global client, is_connected
    if is_connected:
        add_message("[Client] Already connected to the server.")
        return

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        add_message("[Server] Reconnected")
        is_connected = True

        username = username_textbox.get()
        if username:
            client.sendall(username.encode())

        threading.Thread(target=listen_for_messages_from_server, args=(client,), daemon=True).start()
    except:
        add_message("[Error] Reconnection failed. Server is not running.")

def send_message():
    message = message_textbox.get()

    if message != '':
        try:
            # Convert to bytes only if not already in bytes format
            if not isinstance(message, bytes):
                message = message.encode()
            encrypted_message = cipher.encrypt(message)
            client.sendall(encrypted_message)
            message_textbox.delete(0, len(message))
        except:
            messagebox.showerror("Error", "Failed to send message due to server outage. Click 'Reconnect' or try again later.")


def listen_for_messages_from_server(client):
    global is_connected
    while is_connected:
        try:
            encrypted_message = client.recv(2048)
            message = cipher.decrypt(encrypted_message).decode('utf-8')

            if message.startswith("USERS~"):
                users = message.replace("USERS~", "").split(", ")
                update_online_clients(users)
            elif message.startswith("OPEN_PRIVATE_CHAT~"):
                recipient = message.split("~")[1]
                open_private_chat(recipient)
            elif message.startswith("[Private]"):
                handle_private_message(message)
            elif message.startswith("LOGOUT_PRIVATE~"):
                recipient = message.split("~")[1]
                if recipient in private_chat_windows:
                    private_chat_windows[recipient].add_private_message(f"[Server] {recipient} has logged out.")
            elif "[Server]" in message and "has blocked you" in message:
                handle_private_message(message)
            elif message != '':
                username = message.split("~")[0]
                content = message.split("~")[1]
                add_message(f"[{username}] {content}")
        except ConnectionResetError:
            add_message("[Server] Connection lost. Click 'Reconnect' to connect to the server.")
            is_connected = False
            break
        except socket.error as e:
            if e.errno == 10053:
                add_message("[Server] You left the chat.")
                is_connected = False
                break
            else:
                messagebox.showerror("Error", f"Unexpected error occurred: {e}")
                is_connected = False
                break
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error occurred: {e}")
            is_connected = False
            break

class PrivateChatWindow:
    def __init__(self, recipient):
        self.recipient = recipient
        self.root = tk.Toplevel()
        self.root.title(f"Private Chat with {recipient}")
        self.root.geometry("400x500")
        self.root.configure(bg=DARK_GREY)
        self.root.resizable(False, False)

        self.top_frame = tk.Frame(self.root, bg=DARK_GREY)
        self.top_frame.pack(fill="x", padx=5, pady=5)

        self.back_button = tk.Button(self.top_frame, text="<-", font=BUTTON_FONT, bg=DARK_GREY, fg=WHITE, command=self.go_back)
        self.back_button.pack(side=tk.LEFT)

        self.middle_frame = tk.Frame(self.root, bg=DARK_GREY)
        self.middle_frame.pack(fill="both", expand=True, padx=10, pady=(10, 0))

        self.chat_box = scrolledtext.ScrolledText(self.middle_frame, font=SMALL_FONT, bg=SOFT_WHITE, fg=DARK_GREY, wrap=tk.WORD)
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.pack(fill="both", expand=True)

        self.bottom_frame = tk.Frame(self.root, bg=DARK_GREY)
        self.bottom_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.message_textbox = tk.Entry(self.bottom_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY)
        self.message_textbox.pack(side=tk.LEFT, fill="x", expand=True, padx=(0, 10))

        self.block_button = tk.Button(self.bottom_frame, text="Block" if self.recipient not in blocked_users else "Unblock", 
                                      font=BUTTON_FONT, bg=RED if self.recipient not in blocked_users else "orange", 
                                      fg=WHITE, command=self.toggle_block_user)
        self.block_button.pack(side=tk.RIGHT, padx=10)
        
        self.send_button = tk.Button(self.bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=self.send_private_message)
        self.send_button.pack(side=tk.RIGHT)
        self.message_textbox.bind('<Return>', lambda event: self.send_private_message())

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
    
    def send_private_message(self):
        if self.recipient in blocked_users:
            return
        
        message = self.message_textbox.get()
        if message != '':
            try:
                formatted_message = f"PRIVATE~{self.recipient}~{message}"
                # Encrypt the formatted private message
                encrypted_message = cipher.encrypt(formatted_message.encode())
                client.sendall(encrypted_message)
                self.add_private_message(f"[Me] {message}")
                self.message_textbox.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Failed to send private message.")
        else:
            messagebox.showerror("Empty message", "Message cannot be empty")

    def add_private_message(self, message):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, message + '\n')
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)

    def toggle_block_user(self):
        if self.recipient in blocked_users:
            blocked_users.remove(self.recipient)
            self.add_private_message(f"[Server] You unblocked {self.recipient}.")
            self.block_button.config(text="Block", bg=RED)
        else:
            blocked_users.add(self.recipient)
            self.add_private_message(f"[Server] You blocked {self.recipient}.")
            self.block_button.config(text="Unblock", bg="orange")
            
    def go_back(self):
        self.root.destroy()
        open_private_chat()

    def on_close(self):
        del private_chat_windows[self.recipient]  # Remove window from dictionary
        self.root.destroy()

def handle_private_message(message):
    try:
        parts = message.split("~")

        if len(parts) != 2:
            return

        sender = parts[0].replace("[Private] ", "")
        content = parts[1]

        if sender in blocked_users:
            add_message(f"[Server] Message from {sender} blocked.")
            return
        
        # Check if a private chat window is already open with the sender
        if sender in private_chat_windows:
            print(f"Received private message: {message}")
            private_chat_windows[sender].add_private_message(f"[{sender}] {content}")
        else:
            # Open window for recipient
            window = PrivateChatWindow(sender)
            private_chat_windows[sender] = window
            print(f"Received private message: {message}")
            window.add_private_message(f"[{sender}] {content}")
    except Exception as e:
        add_message(f"[Error] {str(e)}")
    
def open_private_chat():
    # Creating new Toplevel window for user selection
    selection_window = tk.Toplevel(root)
    selection_window.title("Select User for Private Chat")
    selection_window.geometry("200x200")
    selection_window.configure(bg=DARK_GREY)

    frame = tk.Frame(selection_window, bg=DARK_GREY)
    frame.pack(pady=10)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    user_listbox = Listbox(frame, font=SMALL_FONT, bg=LIGHT_GREY, fg=DARK_GREY, yscrollcommand=scrollbar.set)
    user_listbox.pack(side=tk.LEFT, fill=tk.BOTH)

    scrollbar.config(command=user_listbox.yview)

    # Populate Listbox with online users
    users = online_users_box.get(1.0, tk.END).strip().split("\n")
    for user in users:
        if user and user != f"->{username_textbox.get()}":  # Avoid selecting own username
            user_listbox.insert(tk.END, user[2:])

    def on_select(event):
        selected_user = user_listbox.get(user_listbox.curselection())
        open_private_chat_window(selected_user)
        selection_window.destroy()

    user_listbox.bind('<<ListboxSelect>>', on_select)


def open_private_chat_window(recipient):
    """Open chat with the selected user."""
    if recipient in private_chat_windows:
        if private_chat_windows[recipient].root.winfo_exists():   # Check if window is still open
            private_chat_windows[recipient].root.lift()
        else:
            private_chat_windows[recipient] = PrivateChatWindow(recipient)    # If not create a new one
    else:
        window = PrivateChatWindow(recipient)
        private_chat_windows[recipient] = window  # Store window in dictionary

def logout():
    global is_connected
    if is_connected:
        try:
            logout_message = cipher.encrypt("LOGOUT".encode())
            client.sendall(logout_message)
            client.close()
            is_connected = False
            add_message("[Client] Disconnected from server.")
            username_textbox.config(state=tk.DISABLED)
            username_button.config(state=tk.DISABLED)
            reconnect_button.config(state=tk.NORMAL)

            online_users_box.config(state=tk.NORMAL)
            online_users_box.delete(1.0, tk.END)
            online_users_box.config(state=tk.DISABLED)
        except:
            messagebox.showerror("Error", "Failed to disconnect properly.")
    else:
        messagebox.showinfo("Info", "You are not connected to the server.")

def on_window_close():
    logout()
    root.destroy()



#GUI
root = tk.Tk()
root.geometry("1040x700")
root.title("LinkClick Chat Client")
root.configure(bg=DARK_GREY)
root.resizable(False, False)

top_frame = tk.Frame(root, bg=DARK_GREY, pady=10)
top_frame.pack(fill="x", padx=10, pady=10)

header_label = tk.Label(top_frame, text="Global Chat", font=HEADER_FONT, bg=DARK_GREY, fg=OCEAN_BLUE)
header_label.pack(pady=(0,5))

host_label = tk.Label(top_frame, text="Host IP: ", font=FONT, bg=DARK_GREY, fg=SOFT_WHITE)
host_label.pack(side=tk.LEFT, padx=(0, 0))

host_textbox = tk.Entry(top_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=10)
host_textbox.insert(0, HOST)
host_textbox.pack(side=tk.LEFT, padx=5)

port_label = tk.Label(top_frame, text="Port: ", font=FONT, bg=DARK_GREY, fg=SOFT_WHITE)
port_label.pack(side=tk.LEFT, padx=(0, 0))

port_textbox = tk.Entry(top_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=7)
port_textbox.insert(0, str(PORT))
port_textbox.pack(side=tk.LEFT, padx=5)

username_label = tk.Label(top_frame, text="Enter Username: ", font=FONT, bg=DARK_GREY, fg=SOFT_WHITE)
username_label.pack(side=tk.LEFT, padx=(0, 0))

username_textbox = tk.Entry(top_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=15)
username_textbox.pack(side=tk.LEFT, padx=10)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=10)

reconnect_button = tk.Button(top_frame, text="Reconnect", font=BUTTON_FONT, bg='#50C878', fg=WHITE, command=reconnect)
reconnect_button.pack(side=tk.LEFT, padx=10)
reconnect_button.config(state=tk.DISABLED)

logout_button = tk.Button(top_frame, text="Logout", font=BUTTON_FONT, bg='#FF6347', fg=WHITE, command=logout)
logout_button.pack(side=tk.LEFT, padx=10)
logout_button.config(state=tk.DISABLED)

middle_frame = tk.Frame(root, bg=LIGHT_GREY, padx=10 , pady=10)
middle_frame.pack(fill="both", expand=True, padx=10, pady=10, side=tk.LEFT)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=SOFT_WHITE, fg=DARK_GREY, wrap=tk.WORD)
message_box.config(state=tk.DISABLED)
message_box.pack(fill="both", expand=True)

message_box.tag_configure('error', foreground=RED)

message_textbox = tk.Entry(middle_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=80)
message_textbox.pack(side=tk.LEFT, padx=0, pady=10)

message_button = tk.Button(middle_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)
message_button.config(state=tk.DISABLED)

right_frame = tk.Frame(root, bg=DARK_GREY, padx=10, pady=10)
right_frame.pack(fill="y", side=tk.RIGHT)

online_label = tk.Label(right_frame, text="Online", font=HEADER_FONT, bg=DARK_GREY, fg=OCEAN_BLUE)
online_label.pack(pady=5)

online_users_box = tk.Text(right_frame, font=SMALL_FONT, bg=SOFT_WHITE, fg=DARK_GREY, height=30, width=20)
online_users_box.config(state=tk.DISABLED)
online_users_box.pack(padx=5, pady=5)

private_chat_button = tk.Button(top_frame, text="Private Chat", font=BUTTON_FONT, bg='#3F51B5', fg=WHITE, command=open_private_chat)
private_chat_button.pack(side=tk.LEFT, padx=10)
private_chat_button.config(state=tk.DISABLED)


def enter_pressed(event):
    if username_textbox['state'] == 'normal':
        connect()
    else:
        send_message()

root.bind('<Return>', enter_pressed)

root.protocol("WM_DELETE_WINDOW", on_window_close)

def main():
    root.mainloop()

if __name__ == "__main__":
    main()