# LinkClick-ChatApp

# Team Members
222-134-014 Nahida Ahmed Chowdhury
222-134-025 Khadiza Sultana Chowdhury Rimi
222-135-028 Naima Rahman 

LinkClick-ChatApp is a simple chat application built using Python's `Tkinter` for the graphical user interface (GUI) and `socket programming` for client-server communication. This app allows users to send public and private messages, view online users, block/unblock users in private chats, and ensures secure communication through encryption.

## Features
- **Real-Time Communication**: Send and receive messages instantly with real-time updates.
- **Public Chat**: Users can send messages to the entire server, and all online users will see them.
- **Private Chat**: Initiate private chats with other users, send and receive encrypted private messages.
- **User Management**: View a list of online users and select anyone for private chat.
- **Block User**: Option to block/unblock a user in private chat.
- **Encryption**: All messages, both public and private, are encrypted using the `cryptography.fernet` encryption method to ensure secure communication.
- **Reconnect**: Users can reconnect to the server if the connection is lost.
- **Client and Server Application**: Includes both the client-side and server-side code, both of which use sockets to communicate.

## Requirements
- Python 3.x
- Tkinter (comes pre-installed with Python)
- Cryptography library (`pip install cryptography`)
- Socket (included in the standard Python distribution)

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/Naima006/LinkClick-ChatApp.git
   ```

2. Install the required dependencies:

   ```bash
   pip install cryptography
   ```

3. Run the application:

   - Start the server by running the `server.py` file:

     ```bash
     python server.py
     ```

   - Then start the client by running the `client.py` file:

     ```bash
     python client.py
     ```

   This will start the client-side application. Make sure the server is running (the server listens on `127.0.0.1` and port `1234` by default). Ensure both the server and client are using the same IP and port settings.

## How It Works

### Server-Side
- The server listens for incoming client connections and handles multiple clients concurrently using threading.
- When a client sends a message, the server decrypts it and broadcasts the message to all connected clients.
- The server also handles private chats, allowing users to send messages to specific users.
- Users can disconnect from the server, and the server will notify other clients that the user has left.

### Client-Side
- Clients can input their username, connect to the server, and send both public and private messages.
- Messages are encrypted before being sent to the server, and they are decrypted upon reception.
- Users can open a private chat window with other users, and block/unblock them.
- If the connection is lost, users can reconnect to the server without losing chat history.


## Code Overview

### **client.py**
- **connect()**: Establishes the connection with the server and listens for messages.
- **send_message()**: Sends encrypted messages using Fernet.
- **listen_for_messages_from_server()**: Handles incoming messages (public, private, etc.).
- **PrivateChatWindow**: Opens a new window for private chats.
- Manages the GUI, user interactions, and message encryption/decryption with Fernet.

### **server.py**
- Listens for client connections and handles multiple clients with threading.
- Manages user sessions and broadcasts messages.
- Handles encryption/decryption for secure communication.
- Notifies clients when a user disconnects.


## How to Use

1. **Login**:
   - Open the application, enter a username, and connect to the server by clicking the **Connect** button.

2. **Send Messages**:
   - Type a message in the textbox and press Enter or click the **Send Message** button.

3. **Logout**:
   - You can disconnect from the server by clicking the **Logout** button.
   - 
4. **Private Chat**:
   - Click the **Private Chat** button to view a list of online users.
   - Select a user to start a private chat.
  
5. **Block/Unblock**:
   - During a private chat, you can block or unblock the other user using the **Block** button.


## Code Explanation

- **client.py**: This is the main client script that handles the entire GUI, socket communication, and message encryption/decryption. The application uses socket connection to communicate with the server.
  
  - **connect()**: Establishes the connection with the server and listens for incoming messages.
  - **send_message()**: Sends a message to the server, encrypted using Fernet.
  - **listen_for_messages_from_server()**: Listens for different types of incoming messages from the server (public, private, etc.).
  - **PrivateChatWindow class**: Creates a new window for private chats with specific users.
  
- **server.py**: This file manages the server-side operations.
  - Listens for incoming connections.
  - Handles message encryption/decryption.
  - Manages multiple clients and broadcasts public and private messages.
