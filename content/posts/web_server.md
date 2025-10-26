+++
date = '2025-10-20T09:45:15+05:30'
draft = false
title = 'Building a Web Server from Scratch in Python'
categories = ["python", "web server"]
+++

I am trying to learn how a web server like nginx work. So I thought of making one myself because the best way to learn something is making it yourself. This will be a multipart series.
In this first part, we'll build a simple, single-threaded server that can handle basic HTTP requests and even has a custom echo endpoint.

## Creating the server

#### Step 1:
We will first create a class in python and name it Server. This Server class will contain all the functionalities of our server.
```python
import socket

class Server():
    def __init__(self, ip:str, port:int, addr=socket.AF_INET, proto=socket.SOCK_STREAM):
        self.addr = addr
        self.proto = proto
        self.IP = ip
        self.PORT = port

        self.server = socket.socket(self.addr, self.proto)
```
We will be using the socket library provided by python.
**Sockets**: Sockets are endpoints of a network connection. It resides in the layer 4 or the transport layer of an OSI model. We can define a socket using a tuple of 4 elements which are :
(local_ip, local_port, remote_ip, remote_port)
1) local_ip -> Server's ip address
2) local_port -> Server's port
3) remote_ip -> Client's ip address
4) remote_port -> Client's port

In the above code we are creating a listening socket using `socket.socket()` and passing the parameters `socket.AF_INET` and `socket.SOCK_STREAM` . `socket.AF_INET` tells the OS that this socket will be using the IPv4 addressing scheme and `socket.SOCK_STREAM` tells the os that we will be using the TCP protocol. If you want to use the UDP protocol then you can replace `socket.SOCK_STREAM` with `socket.SOCK_DGRAM`.

#### Step 2:
Now we will create a method to start the server:
```python
    def start_server(self):
        try:
             with self.server:
                self.server.bind((self.IP, self.PORT))
                self.server.listen()

                while True:
                    conn, addr = self.server.accept()
        except Exception as e:
            print(f"Server could not be started {e}")
```
We will first bind the above socket to an IP and PORT using `self.server.bind((self.IP, self.PORT))` . Then we will call the `listen()` function which will listen for incoming client connections and store them in a  backlog queue. When this queue fills up the OS will drop any further new connections. We can set the limit to how many pending request that can be handled by passing the number to the listen function i.e. `listen(5)`.

Here's what happens under the hood:
1) Client sends a SYN packet to our server
2) Kernel sees your socket is in LISTEN state and replies with a SYN-ACK message.
3) Client replies ACK
4) TCP connection is now established, and it goes into the accept queue.
5) Then we will call `accept()` . Then server will give the first pending connction from that queue. 
The accept method will return a new established socket and store it in the `conn` variable and the address of the client in the `addr` variable.
We will be using this established socket for communications with the client.

#### Step 3:
Now we will add a method for creating the http responses that our server will be sending:

```python
    def create_http_response(self, msg):
        """
        msg = {
            status: int,
            status_info: str, 
            headers: {},
            body: str
        }
        """
        response = ""
        status = msg['status']
        status_info = msg['status_info']

        response += f"HTTP/1.1 {status} {status_info}\r\n"
        for header in msg['headers'].keys():
            response += f"{header}: {msg['headers'][header]}\r\n"

        # Blank line between header and body 
        response += "\r\n"

        response += msg['body']

        return response

```
A HTTP response consists of a response line, headers and body , each separated by a CRLF(Carriage Return Line Feed) i.e `\r\n`.

#### Step 4:
Now we will create a method to add endpoints to a dictionary named `endpoints`.
So our constructor would look like :
```python
    def __init__(self, ip:str, port:int, addr=socket.AF_INET, proto=socket.SOCK_STREAM):
        self.addr = addr
        self.proto = proto
        self.IP = ip
        self.PORT = port
        self.endpoints = {} # Added

        self.server = socket.socket(self.addr, self.proto)


```

The method for adding the endpoints:
```python
    def add_endpoint(self, path, method = "GET", handler=None):
        key = f"{method} {path}" # To match like : GET /index.html ...
        self.endpoints[key] = handler
```

#### Step 5:
We will now add a method for handling the clients.

First we will iterate and get all the incoming data until we find `\r\n\r\n` since that is the indication that the header section is finished.
Then we will read the header `Content-Length` to get the size of the body section and we will check how much of it is already recieved.Then we will get the rest of the body.

It will then check the incoming request against all registered endpoints. If it finds a match, it calls the handler, sends the response, and breaks out of the loop. If the loop finishes without finding any matches, it then sends a single 404 Not Found response.

```python
    def handle_client(self, conn):
        try:
            # Read headers first
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
            
            if not data:
                return
                
            # Split headers and potential body
            headers_end = data.find(b"\r\n\r\n")
            headers_part = data[:headers_end]
            body_data = data[headers_end + 4:]
        
            # Parse headers to get Content-Length if present
            headers = headers_part.decode('utf-8').split('\r\n')
            content_length = 0
            
            for header in headers:
                if header.lower().startswith('content-length:'):
                    content_length = int(header.split(':')[1].strip())
                    break
            
            # Read remaining body data if Content-Length is specified
            while len(body_data) < content_length:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                body_data += chunk
            
            # Reconstruct full request
            full_request = headers_part + b"\r\n\r\n" + body_data
            request = full_request.decode('utf-8')
            
            response_sent = False
            for endpoint_key, handler in self.endpoints.items():
                if request.startswith(endpoint_key):
                    response = handler(request)
                    conn.send(self.create_http_response(response).encode())
                    response_sent = True
                    break
    
            if not response_sent:
                response = {
                    "status": 404,
                    "status_info": "Not Found",
                    "headers": {'Content-Type': 'text/plain', 'Content-Length': '9'},
                    "body": "Not Found"
                }
                conn.send(self.create_http_response(response).encode())
                
        except Exception as e:
            print(f"Error handling client: {e}")
            try:
                error_response = {
                    "status": 500,
                    "status_info": "Internal Server Error",
                    "headers": {'Content-Type': 'text/plain', 'Content-Length': '21'},
                    "body": "Internal Server Error"
                }
                conn.send(self.create_http_response(error_response).encode())
            except:
                pass


```

And then add this function to the `start_server()` function to handle the clients: We will put it inside a `While True` loop such that our server doesnot close after handling only a single connection and accepts new connections from the queue.

```python
    def start_server(self):
        try:
             with self.server:
                self.server.bind((self.IP, self.PORT))
                self.server.listen()

                while True:
                    conn, addr = self.server.accept()
                    with conn:
                        self.handle_client(conn)
        except Exception as e:
            print(f"Server could not be started {e}")
```

#### Step 6:
Now we will add a very simple echo endpoint to our server that will echo back anything it receives on the path /echo/.

```python
def echoHandler(request):
    echo_str = request.split("\r\n")[0].split(" ")[1].split("/")[2] # Note: This is a naive parsing method for demonstration. A real server would use a more robust parser.
    msg = {
        "status": 200,
        "status_info": "OK",
        "headers": {'Content-Length': str(len(echo_str)), 'Content-Type': "text/plain"},
        "body": echo_str
    }

    return msg

```
Here we do a bit of string manipulation to get the string from the path /echo/x and then send a response containing the string `x`.

Hence we have created a simple HTTP server using python that supports endpoints. We have tried to make it as modular as possible . Here is the complete code
```python
import socket
import os

class Server():
    def __init__(self, ip:str, port:int, addr=socket.AF_INET, proto=socket.SOCK_STREAM):
        self.addr = addr
        self.proto = proto
        self.IP = ip
        self.PORT = port
        self.endpoints = {}

        self.server = socket.socket(self.addr, self.proto)

    def handle_client(self, conn):
        try:
            # Read headers first
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
            
            if not data:
                return
                
            # Split headers and potential body
            headers_end = data.find(b"\r\n\r\n")
            headers_part = data[:headers_end]
            body_data = data[headers_end + 4:]
        
            # Parse headers to get Content-Length if present
            headers = headers_part.decode('utf-8').split('\r\n')
            content_length = 0
            
            for header in headers:
                if header.lower().startswith('content-length:'):
                    content_length = int(header.split(':')[1].strip())
                    break
            
            # Read remaining body data if Content-Length is specified
            while len(body_data) < content_length:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                body_data += chunk
            
            # Reconstruct full request
            full_request = headers_part + b"\r\n\r\n" + body_data
            request = full_request.decode('utf-8')
            
            response_sent = False
            for endpoint_key, handler in self.endpoints.items():
                if request.startswith(endpoint_key):
                    response = handler(request)
                    conn.send(self.create_http_response(response).encode())
                    response_sent = True
                    break
    
            if not response_sent:
                response = {
                    "status": 404,
                    "status_info": "Not Found",
                    "headers": {'Content-Type': 'text/plain', 'Content-Length': '9'},
                    "body": "Not Found"
                }
                conn.send(self.create_http_response(response).encode())
                
        except Exception as e:
            print(f"Error handling client: {e}")
            try:
                error_response = {
                    "status": 500,
                    "status_info": "Internal Server Error",
                    "headers": {'Content-Type': 'text/plain', 'Content-Length': '21'},
                    "body": "Internal Server Error"
                }
                conn.send(self.create_http_response(error_response).encode())
            except:
                pass


    def add_endpoint(self, path, method = "GET", handler=None):
        key = f"{method} {path}"
        self.endpoints[key] = handler

    def start_server(self):
        try:
             with self.server:
                self.server.bind((self.IP, self.PORT))
                self.server.listen()

                while True:
                    conn, addr = self.server.accept()
                    with conn:
                        self.handle_client(conn)
        except Exception as e:
            print(f"Server could not be started {e}")

    def create_http_response(self, msg):
        """
        msg = {
            status: int,
            status_info: str, 
            headers: {},
            body: str
        }
        """
        response = ""
        status = msg['status']
        status_info = msg['status_info']

        response += f"HTTP/1.1 {status} {status_info}\r\n"
        for header in msg['headers'].keys():
            response += f"{header}: {msg['headers'][header]}\r\n"

        # Blank line between header and body 
        response += "\r\n"

        response += msg['body']

        return response

# ... (the Server class ends here)

# Define endpoint handlers outside the Server class

def echoHandler(request):
    echo_str = request.split("\r\n")[0].split(" ")[1].split("/")[2]
    msg = {
        "status": 200,
        "status_info": "OK",
        "headers": {'Content-Length': str(len(echo_str.encode())), 'Content-Type': "text/plain"},
        "body": echo_str
    }

    return msg

if __name__ == "__main__":
    server = Server("127.0.0.1", 40000)
    server.add_endpoint("/echo/", handler=echoHandler)
    server.start_server()

```
In the next part we will try to upgrade our server such that it can handle multiple concurrent connections.


