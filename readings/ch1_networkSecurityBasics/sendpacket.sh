#!/bin/env python3
import socket

data = b"hello, server\n"
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(data, ("10.9.0.5", 9090))
