import asyncio
import websockets


async def send_ip(ip):
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri) as websocket:
        await websocket.send(ip)
        response = await websocket.recv()
        print(response)

# Legg til IP-adressene du vil teste
ip_addresses = [
    "37.187.101.220",
    "51.38.49.222",
    "49.247.27.18",
    "159.89.175.201",
    "138.68.250.220",
    "165.232.183.101",
    "114.207.244.90",
    "43.134.91.43",
    ]

for ip in ip_addresses:
    asyncio.get_event_loop().run_until_complete(send_ip(ip))
