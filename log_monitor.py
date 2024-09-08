import asyncio
import websockets
import subprocess
import re

# Adresse til WebSocket-serveren
WS_SERVER = "ws://192.168.41.83:8000/ws"

# Regex for å finne IP-adresser i auth.log
ip_regex = re.compile(r"(\d{1,3}\.){3}\d{1,3}")

# Kommando for å kjøre `tail -f` på auth.log
TAIL_COMMAND = ["tail", "-f", "/var/log/auth.log"]


async def monitor_log_and_send():
    process = subprocess.Popen(TAIL_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    async with websockets.connect(WS_SERVER) as websocket:
        while True:
            line = process.stdout.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue

            # Dekode linjen og finn IP-adresser
            line = line.decode("utf-8")
            print(f"Read line: {line.strip()}")
            match = ip_regex.search(line)
            if match:
                ip = match.group()
                print(f"Found IP: {ip}")
                await websocket.send(ip)

async def main():
    await monitor_log_and_send()

if __name__ == "__main__":
    asyncio.run(main())
