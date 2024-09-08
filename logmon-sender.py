# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import subprocess
import re
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

# Load environment variables from .env file
load_dotenv()

# Get configuration values from environment variables
REST_SERVER = os.getenv("REST_SERVER", "http://localhost:8000/connection")

# Regex for å finne IP-adresser og porter i auth.log
log_regex = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*nvalid user (?P<username>\S+) from (?P<source_ip>(\d{1,3}\.){3}\d{1,3}) port (?P<source_port>\d+)'
    #r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>(\d{1,3}\.){3}\d{1,3}) port (?P<source_port>\d+)'

)

# Kommando for å kjøre `tail -f` på auth.log
TAIL_COMMAND = ["tail", "-f", "/var/log/auth.log"]

def parse_log_timestamp(timestamp):
    now = datetime.now()
    log_time = datetime.strptime(f"{now.year} {timestamp}", "%Y %b %d %H:%M:%S")
    return log_time

async def monitor_log_and_send():
    process = subprocess.Popen(TAIL_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    async with aiohttp.ClientSession() as session:
        while True:
            line = process.stdout.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue

            # Dekode linjen og finn IP-adresser og porter
            line = line.decode("utf-8")
            print("Read line: {}".format(line.strip()))
            match = log_regex.search(line)
            if match:
                timestamp = match.group("timestamp")
                log_time = parse_log_timestamp(timestamp)
                time_diff = (datetime.now() - log_time).total_seconds()

                # Sjekk om innslaget er nyere enn 2-3 sekunder
                if time_diff > 3:
                    print("Log entry is too old, skipping netstat check")
                    continue

                source_ip = match.group("source_ip")
                source_port = int(match.group("source_port"))
                username = match.group("username")
                print("Found failed login: {}:{} -> {}@our-server".format(source_ip, source_port, username))

                # Bruk netstat for å finne destinasjons-IP og port
                netstat_command = ["netstat", "-nap"]
                netstat_process = subprocess.Popen(netstat_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                netstat_output = netstat_process.communicate()[0].decode("utf-8")

                # Log netstat output for debugging
                # print("Netstat output:\n", netstat_output)

                # Finn destinasjonsporten for SSH uten å inkludere tilkoblingsstatus
                ssh_port_regex = re.compile(
                    fr'(?P<local_ip>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):(?P<local_port>\d+)\s+'
                    fr'(?P<foreign_ip>{re.escape(source_ip)}):(?P<foreign_port>{source_port})\s+'
                )

                netstat_match = ssh_port_regex.search(netstat_output)
                if netstat_match:
                    dest_ip = netstat_match.group("local_ip")
                    dest_port = int(netstat_match.group("local_port"))
                    print("\033[92mFound connection: {}:{} -> {}:{} ({}\033[0m)".format(source_ip, source_port, dest_ip, dest_port, username))
                    async with session.post(REST_SERVER, params={
                        'source_ip': source_ip,
                        'source_port': source_port,
                        'dest_ip': dest_ip,
                        'dest_port': dest_port,
                        'username': username
                    }) as response:
                        if response.status != 200:
                            print(f"Failed to send connection info: {source_ip}:{source_port} -> {dest_ip}:{dest_port} with status {response.status}")
                        else:
                            print(f"\033[92mSuccessfully sent connection info: {source_ip}:{source_port} -> {dest_ip}:{dest_port}\033[0m")
                            # print(f"Successfully sent connection info: {source_ip}:{source_port} -> {dest_ip}:{dest_port}")
                else:
                    print(f"Could not find netstat information for {source_ip}:{source_port}")

async def main():
    await monitor_log_and_send()

if __name__ == "__main__":
    asyncio.run(main())
