#!/usr/bin/env python

import zlib
import gzip
import json
import socket
from io import BytesIO
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

HOST = '0.0.0.0'            # Listen on all interfaces
PORT = 9401                 # Port for GELF TCP
MAX_CONNECTIONS = 5         # Maximum number of connections

# Create a TCP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if not s:
    logger.critical('Socket creation failed!')
    sys.exit()

# Bind socket to local host and port
try:
    s.bind((HOST, PORT))
    s.listen(MAX_CONNECTIONS)  # Start listening, max 5 connections
except socket.error as e:
    logger.critical('Bind failed. Error Code: ' + str(e))
    sys.exit()

ip, port = s.getsockname()
logger.info(f"Listening on IP address: {ip}, Port: {port}")


def is_gzip(data):
    return data[:2] == b'\x1f\x8b'


def is_zlib(data):
    return data[:2] == b'\x78\x9c'


def decompress_data(data: bytes):
    if is_gzip(data):
        try:
            # Try to decompress the data with gzip
            with gzip.GzipFile(fileobj=BytesIO(data)) as gzip_file:
                decompressed_data = gzip_file.read()
                logger.info("Data decompressed with gzip")
                return decompressed_data
        except OSError as e:
            logger.error(f"Gzip decompress failed: {e}")
            return None
    elif is_zlib(data):
        try:
            # If data is compressed with zlib
            decompressed_data = zlib.decompress(data)
            logger.info("Data decompressed with zlib")
            return decompressed_data
        except zlib.error as e:
            logger.error(f"Zlib decompress failed: {e}")
            return None
    else:
        # If data is not compressed
        logger.info("Data is not compressed")
        return data


while True:
    conn, addr = s.accept()  # Accept connection
    logger.info(f"Connection from {addr}")

    try:
        data = b""
        while True:
            chunk = conn.recv(8192)  # Receive data in chunks of 8192 bytes
            if not chunk:  # If no more data is received
                break
            data += chunk

            # Check if the message contains a nullbyte (end-of-message in GELF TCP)
            if b'\x00' in data:
                # Split messages on nullbyte
                messages = data.split(b'\x00')

                for message in messages:
                    if message:  # If there is a message to process
                        try:
                            # Try to decompress if necessary
                            decompressed_message = decompress_data(message)
                            # Parse JSON
                            json_message = json.loads(decompressed_message)
                            logger.info(f"Received JSON message: {json_message}")

                            # Do something with the message here

                        except json.JSONDecodeError:
                            logger.error("Failed to parse JSON message")

                # Zero out data after processing
                data = b""

    except Exception as e:
        logger.critical(f"Error during data reception: {e}")

    finally:
        conn.close()  # Close the connection
