# -*- coding: utf-8 -*-
# This script is used to monitor a log file for connection information and send it to a REST API.
# It uses asyncio to monitor the log file and aiohttp to send the data to the REST API.
# The script also uses the watchdog library to monitor the log file for changes (e.g. log rotation).
# The script is written to handle logs from Mikrotik routers, but can be adapted to other log formats.
# Forward the syslogs to the host running this script using rsyslog or similar.
import asyncio
import aiohttp
import subprocess
import re
# import socket
import os
import csv
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
from ipaddress import ip_address

# Load environment variables from .env file
# Create your own .env file with the following variables:
# REST_SERVER=http://localhost:8000/connection
# LOG_PREFIX=Mikrotik
# IGNORE_FROM_RFC1918=false
# IGNORE_CONNECTION_STATE=
# LOG_FILE=/var/log/syslog

load_dotenv()

# Get configuration values from environment variables
REST_SERVER = os.getenv("REST_SERVER", "http://localhost:8000/connection")
LOG_PREFIX = os.getenv("LOG_PREFIX", "Mikrotik")
IGNORE_FROM_RFC1918 = os.getenv("IGNORE_FROM_RFC1918", "false").lower() == "true"
IGNORE_CONNECTION_STATES = os.getenv("IGNORE_CONNECTION_STATE", "").lower().split(",")
LOG_FILE = os.getenv("LOG_FILE", "/var/log/syslog")

# log_file = "/var/log/syslog"  # Path to your syslog

# The regex is used to extract the connection information from the log line
# Must be adjusted to match the log format of your system
# TODO: Create a method to include separate files for custom regex patterns
log_regex = re.compile(
    r'connection-state:(?P<connection_state>\w+).*proto\s+(?P<protocol>[A-Z]+).* '
    r'(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<source_port>\d+)->'
    r'(?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dest_port>\d+)'
)


# File path for the IANA port numbers CSV
CSV_FILE_PATH = "service-names-port-numbers.csv"
CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

# Dictionary to store the port information
port_service_mapping = {}


def download_csv():
    if not os.path.exists(CSV_FILE_PATH):
        print("Downloading port numbers CSV file...")
        response = requests.get(CSV_URL)
        with open(CSV_FILE_PATH, 'wb') as f:
            f.write(response.content)
        print("Download complete.")


def load_port_mappings():
    print("Loading port mappings from CSV...")
    with open(CSV_FILE_PATH, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            service_name = row['Service Name']
            port_number = row['Port Number']
            protocol = row['Transport Protocol'].lower()
            description = row['Description']

            if port_number.isdigit():
                key = (int(port_number), protocol)
                port_service_mapping[key] = service_name or description or "Unassigned"
    print("Port mappings loaded.")


def get_port_description(port, protocol):
    return port_service_mapping.get((port, protocol.lower()), "Unknown Port")


def is_rfc1918(ip):
    # Check if the IP address is an RFC1918 address (private address)
    addr = ip_address(ip)
    return addr.is_private


class LogRotateHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            self.callback()


async def process_log_line(line, session):
    line = line.decode("utf-8").strip()
    print("Analyzing line: {}".format(line))
    match = log_regex.search(line)
    if match:
        print("Match found!")
        connection_state = match.group("connection_state").lower()
        source_ip = match.group("source_ip")
        source_port = int(match.group("source_port"))
        dest_ip = match.group("dest_ip")
        dest_port = int(match.group("dest_port"))
        protocol = match.group("protocol")

        # Ignore if the IP address is an RFC1918 address and IGNORE_FROM_RFC1918 is set to true
        if IGNORE_FROM_RFC1918 and is_rfc1918(source_ip):
            print(f"Ignoring RFC1918 source IP: {source_ip}")
            return

        # Ignore if the connection state is in the list of ignored states (IGNORE_CONNECTION_STATES)
        if connection_state in IGNORE_CONNECTION_STATES:
            print(f"Ignoring connection state: {connection_state}")
            return

        # Look up the port descriptions using the CSV data
        source_port_desc = get_port_description(source_port, protocol)
        dest_port_desc = get_port_description(dest_port, protocol)

        print(f"\033[92mFound connection: {source_ip}:{source_port} ({source_port_desc}) -> {dest_ip}:{dest_port} ({dest_port_desc}) ({protocol})\033[0m")

        try:
            async with session.post(REST_SERVER, params={
                'source_ip': source_ip,
                'source_port': source_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'protocol': protocol,
                'connection_state': connection_state
            }, timeout=10) as response:  # Set a timeout for the request
                if response.status != 200:
                    print(f"Failed to send connection info: {source_ip}:{source_port} -> {dest_ip}:{dest_port} with status {response.status}")
                else:
                    print(f"\033[92mSuccessfully sent connection info: {source_ip}:{source_port} -> {dest_ip}:{dest_port}\033[0m")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"Error sending connection info: {e}")


async def monitor_log():
    async with aiohttp.ClientSession() as session:
        process = subprocess.Popen(["tail", "-F", LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        while True:
            line = process.stdout.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            await process_log_line(line, session)


def restart_log_monitor():
    print("Log rotated, restarting log monitor...")
    asyncio.ensure_future(monitor_log())


def start_watchdog():
    event_handler = LogRotateHandler(restart_log_monitor)
    observer = Observer()
    observer.schedule(event_handler, path=LOG_FILE, recursive=False)
    observer.start()


async def main():
    download_csv()
    load_port_mappings()
    start_watchdog()
    await monitor_log()

if __name__ == "__main__":
    asyncio.run(main())
