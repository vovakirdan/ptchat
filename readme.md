# PTCHAT
## UDP and message based
**Functional (currently minimal):**
* manages multiple clients
* allows multiple users
* processes text messages
* supports public chats, tagging users, and private messages.

# Usage
## Step 1: Start the Server
### 1. Run the compiled executable:

```bash
./chat_server 8081
```
This starts the server on port 8081. You can specify a different port as needed.

### 2. Output:

* The server should print:
```bash
Chat server started on port 8081.
```
* If the server cannot start (e.g., due to a port conflict), check that the port isn't in use by another process:
```bash
sudo netstat -tuln | grep 8081
```
Stop the conflicting process or use another port.
## Step 2: Connect Clients
### 1. Using Netcat (nc):

* Open a terminal and run:
```bash
nc 127.0.0.1 8081
```
* This connects a client to the server.
### 2. Using Multiple Clients:

* Open multiple terminal windows and repeat the nc command for each.
* Each connected client will act as a chat participant.
### 3. Interacting with the Chatroom:

* Type messages in one terminal, and they should broadcast to all other connected clients.
* Use the following commands:
    * `~:lu:` List all users and their online/offline status.
    * `~:q!:` Sign out from the chatroom.
    * Send regular messages, tagged messages (`~-@user: Hello`), or private messages (`~->user: Hi`).
## Step 3: Testing
### 1. Functional Testing:

* Verify that broadcasting works:
    * Connect multiple clients.
    * Send a message from one client and confirm it appears on all others.
* Test private messages and tags:
    * Send a message using `~->` or `~-@` syntax and verify it reaches the intended client.
### 2. Edge Cases:

* Try invalid commands or inputs.
* Test with multiple users connecting and disconnecting simultaneously.
### 3. Security Testing:

* Attempt to send malformed commands or data to test the server's resilience.
* Check if unauthorized users can bypass authentication.
## Step 4: Deploying the Server
### 1. Local Deployment:

* Run the server on your machine and have clients connect using your local IP:
```bash
./chat_server 8081
```
### 2. Remote Deployment:

* Deploy the server on a remote machine:
    * Install your server on a VPS (like AWS, DigitalOcean, etc.).
    * Compile and run it on the remote machine.
* Clients can connect using the server's public IP:
```bash
nc <server-ip> 8081
```
### 3. Firewall Configuration:

* Ensure the server's port is open for inbound traffic:
```bash
sudo ufw allow 8081
```
### 4. Running as a Background Service:

* Use `screen` or `tmux` to keep the server running after logging out:
```bash
screen ./chat_server 8081
```
* Detach the session with Ctrl+A, D.
### 5. Systemd Service:

* Create a service file for systemd:
```bash
sudo nano /etc/systemd/system/chat_server.service
```
Contents:
```ini
[Unit]
Description=Chat Server Service
After=network.target

[Service]
ExecStart=/path/to/chat_server 8081
Restart=always

[Install]
WantedBy=multi-user.target
```
* Enable and start the service:
```bash
sudo systemctl enable chat_server
sudo systemctl start chat_server
```
## Step 5: Extending the Chatroom
### 1. Improved Client Interface:

* Write a lightweight client in Python or JavaScript with a GUI or web interface.
* Example in Python:
```python
import socket

HOST = '127.0.0.1'  # Server IP
PORT = 8081         # Server Port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Connected to chatroom!")
    while True:
        message = input("You: ")
        if message.lower() == "~:q!":
            break
        s.sendall(message.encode())
        data = s.recv(1024)
        print(f"Server: {data.decode()}")
```
### 2. WebSocket Integration:

* Extend your server to use WebSockets for real-time chat over HTTP.
* Use libraries like `libwebsockets` in C.
### 3. Database Integration:

* Add a database (e.g., SQLite or PostgreSQL) to persist user data.
### 4. Logging:

* Add a logging system to record messages, user actions, and server activity.
## Step 6: Monitoring and Maintenance
### 1. Monitor Logs:

* If you used systemd, check logs with:
bash
sudo journalctl -u chat_server

### 2. Performance Testing:

* Use tools like Apache Bench (ab) or custom scripts to test how many clients the server can handle simultaneously.
### 3. Scaling:

* For higher traffic, consider using load balancers and multiple server instances.