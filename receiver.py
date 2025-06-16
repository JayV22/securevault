# receiver.py
import socket
import sys

def receive_file(save_as="received.secure", port=9999):
    s = socket.socket()
    s.bind(('', port))
    s.listen(1)

    print(f"Waiting for connection on port {port}...")
    conn, addr = s.accept()
    print(f"Connected by {addr}")

    with open(save_as, 'wb') as f:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            f.write(data)

    conn.close()
    print(f"File saved as {save_as}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python receiver.py <output_filename> <port>")
    else:
        receive_file(sys.argv[1], int(sys.argv[2]))
