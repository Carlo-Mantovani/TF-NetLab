import socket
import time


def main():
    while True:
        # send when user press enter
        print('Sending message')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto('Hello World'.encode(), ('172.20.0.1', 8001))
        time.sleep(10)

if __name__ == '__main__':
    main()