import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

HOST = '127.0.0.1'
PORT = 1234

DARK_GREY = '#2E2E2E'
LIGHT_GREY = '#D3D3D3'
OCEAN_BLUE = '#5DADE2'
SOFT_WHITE = '#F4F6F7'
WHITE = "white"
FONT = ("Helvetica", 14)
BUTTON_FONT = ("Helvetica", 13, "bold")
SMALL_FONT = ("Helvetica", 11)
HEADER_FONT = ("Helvetica", 16, "bold")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
is_connected = False  

def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)

def connect():
    global client, is_connected
    if is_connected:
        add_message("[Client] Already connected to the server.")
        return

    try:
        client.connect((HOST, PORT))
        add_message("[Server] Successfully connected to the server")
        is_connected = True
    except:
        add_message(f"[Error] Connection to server {HOST}:{PORT} failed.")
        return

    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty!")

    threading.Thread(target=listen_for_messages_from_server, args=(client,)).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)

def reconnect():
    global client, is_connected
    if is_connected:
        add_message("[Client] Already connected to the server.")
        return

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        add_message("[Server] Reconnected to the server")
        is_connected = True

        username = username_textbox.get()
        if username:
            client.sendall(username.encode())

        threading.Thread(target=listen_for_messages_from_server, args=(client,), daemon=True).start()
    except:
        add_message("[Error] Reconnection failed. Server may not be running.")

def send_message():
    message = message_textbox.get()
    if message != '':
        try:
            client.sendall(message.encode())
            message_textbox.delete(0, len(message))
        except:
            messagebox.showerror("Error", "Failed to send message. Server might be down. Or you might forgot to click 'Reconnect'.")
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")

def listen_for_messages_from_server(client):
    global is_connected
    while is_connected:
        try:
            message = client.recv(2048).decode('utf-8')
            if message != '':
                username = message.split("~")[0]
                content = message.split("~")[1]
                add_message(f"[{username}] {content}")
        except ConnectionResetError:
            add_message("[Server] Connection lost. Please restart the server and click 'Reconnect'.")
            is_connected = False
            break
        except socket.error as e:
            if e.errno == 10053:
                add_message("[Error] Connection aborted by your host machine.")
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

def logout():
    global is_connected
    if is_connected:
        try:
            client.sendall("LOGOUT".encode()) 
            client.close()
            is_connected = False
            add_message("[Client] Disconnected from server.")
            username_textbox.config(state=tk.NORMAL)
            username_button.config(state=tk.NORMAL)
        except:
            messagebox.showerror("Error", "Failed to disconnect properly.")
    else:
        messagebox.showinfo("Info", "You are not connected to the server.")

root = tk.Tk()
root.geometry("750x650")
root.title("LinkClick Chat Client")
root.configure(bg=DARK_GREY)
root.resizable(False, False)

top_frame = tk.Frame(root, bg=DARK_GREY, pady=10)
top_frame.pack(fill="x", padx=10, pady=10)

header_label = tk.Label(top_frame, text="LinkClick Chat", font=HEADER_FONT, bg=DARK_GREY, fg=OCEAN_BLUE)
header_label.pack()

username_label = tk.Label(top_frame, text="Enter Username: ", font=FONT, bg=DARK_GREY, fg=SOFT_WHITE)
username_label.pack(side=tk.LEFT, padx=(10, 0))

username_textbox = tk.Entry(top_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=25)
username_textbox.pack(side=tk.LEFT, padx=10)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=10)

reconnect_button = tk.Button(top_frame, text="Reconnect", font=BUTTON_FONT, bg='#FF6347', fg=WHITE, command=reconnect)
reconnect_button.pack(side=tk.LEFT, padx=5)

logout_button = tk.Button(top_frame, text="Logout", font=BUTTON_FONT, bg='#FF6347', fg=WHITE, command=logout)
logout_button.pack(side=tk.LEFT, padx=5)

middle_frame = tk.Frame(root, bg=LIGHT_GREY, padx=10, pady=10)
middle_frame.pack(fill="both", expand=True, padx=10, pady=10)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=SOFT_WHITE, fg=DARK_GREY, wrap=tk.WORD)
message_box.config(state=tk.DISABLED)
message_box.pack(fill="both", expand=True)

bottom_frame = tk.Frame(root, bg=DARK_GREY, pady=10)
bottom_frame.pack(fill="x", padx=10, pady=10)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=LIGHT_GREY, fg=DARK_GREY, width=55)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)

def enter_pressed(event):
    if username_textbox['state'] == 'normal':
        connect()
    else:
        send_message()

root.bind('<Return>', enter_pressed)

def main():
    root.mainloop()

if __name__ == "__main__":
    main()