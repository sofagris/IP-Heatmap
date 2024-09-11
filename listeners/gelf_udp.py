#!/usr/bin/env python

import zlib
import gzip
import json
import socket
from io import BytesIO
import sys
from logging import getLogger

from listeners.event_listener import Listeners


logger = getLogger(__name__)
# logger.basicConfig(level=logger.warn)


# Async UDP listener function
async def udp_listener(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if not s:
        logger.critical('Socket creation failed!')
        sys.exit()

    try:
        s.bind((host, port))
    except socket.error as e:
        logger.critical('Bind failed. Error Code : ' + str(e[0]) + ' Message ' + e[1])
        sys.exit()

    ip, port = s.getsockname()
    logger.info(f"Listening on IP address: {ip}, Port: {port}")

    while True:
        data, addr = s.recvfrom(8192)   # Max buffer size is 8192 bytes

        # message = decompress_data(data)
        json_message = json.loads(decompress_data(data))
        logger.info(json_message)

        # Trigger GELF_DATA event
        Listeners.trigger_event("GELF_DATA", json_message)


def decompress_data(data: bytes):
    try:
        # Try to decompress the data with gzip
        with gzip.GzipFile(fileobj=BytesIO(data)) as gzip_file:
            decompressed_data = gzip_file.read()
            logger.info("Data decompressed with gzip")
            return decompressed_data
    except OSError:
        logger.info("Gzip failed, trying zlib...")

    try:
        # If gzip fails, try zlib
        decompressed_data = zlib.decompress(data)
        logger.info("Data decompressed with zlib")
        return decompressed_data
    except zlib.error as e:  # If both fail, return None
        logger.critical(f"Zlib decompress failed : {e}")
        return None
