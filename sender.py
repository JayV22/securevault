# sender.py
import socket
import sys

def send_file(filename, host='localhost', port=9999):
    s = socket.socket()
    s.connect((host, port))

    with open(filename, 'rb') as file:
        data = file.read()
        s.sendall(data)

    s.close()
    print(f"File sent to {host}:{port}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python sender.py <file> <host> <port>")
    else:
        send_file(sys.argv[1], sys.argv[2], int(sys.argv[3]))
