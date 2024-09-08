# This is a simple FastAPI application that uses WebSockets to communicate with clients in real-time.
# The purpose of this application is to demonstrate how you can view real-time events on a map.
# Configuration is done using environment variables, which are read from a .env file.
# There is a lot of cleanup to be done in this code, but it should work as a starting point for your own projects.
# TODO: Restructure the code to use CRUD operations and separate the logic into different files, such as models.py, crud.py, etc.
# TODO: Separate the WebSocket logic into a separate file, such as websocket.py
# TODO: Create separate routes for different types of data, such as /api/geoip, /api/whois, /api/connections, etc.
# TODO: Create MongoDB models for the different types of data, such as GeoIP, WHOIS, Connections, etc.
 
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import FileResponse
import requests
import logging
import os
import sqlite3
from dotenv import load_dotenv
from cachetools import TTLCache
from typing import Optional
import csv
import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import time
from datetime import datetime, timedelta
import ipaddress
from collections import deque
import pymongo


logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
load_dotenv()

IPIFO_TOKEN = os.getenv("IPIFO_TOKEN")
HTTP_IP = os.getenv("HTTP_IP", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", 8000))
CACHE_TTL = int(os.getenv("CACHE_TTL", 3600))
CACHE_MAXSIZE = int(os.getenv("CACHE_MAXSIZE", 1000))

# Read MongoDB configuration from .env file
mongo_host = os.getenv("MONGO_HOST", "192.168.41.193")
mongo_port = int(os.getenv("MONGO_PORT", 27017))
mongo_user = os.getenv("MONGO_USER", "root")
mongo_pass = os.getenv("MONGO_PASS", "password")
mongo_db = os.getenv("MONGO_DB", "cyber_analysis")
mongo_fw_collection = os.getenv("MONGO_FW_COLLECTION", "firewall_logs")
mongo_nginx_collection = os.getenv("MONGO_NGINX_COLLECTION", "nginx_logs")
mongo_postfix_collection = os.getenv("MONGO_POSTFIX_COLLECTION", "postfix_logs")
mongo_whois_collection = os.getenv("MONGO_WHOIS_COLLECTION", "whois_info")
mongo_geoip_collection = os.getenv("MONGO_GEOIP_COLLECTION", "geoip_info")
mongo_ipwhois_collection = os.getenv("MONGO_IPWHOIS_COLLECTION", "ipwhois_info")
mongo_user_collection = os.getenv("MONGO_USER_COLLECTION", "user_info")

# An deque to store the last latency measurements and the timestamps for each insert.
latency_times = deque(maxlen=1000)  # Limit to 1000 records. 
insert_times = deque(maxlen=1000)  # Timestamps for each insert.

# Create a MongoDB client
client = pymongo.MongoClient(
    host=mongo_host,
    port=mongo_port,
    username=mongo_user,
    password=mongo_pass
)

# Select the database
db = client[mongo_db]

# MongoDB collections
firewall_collection = db[mongo_fw_collection]
nginx_collection = db[mongo_nginx_collection]
postfix_collection = db[mongo_postfix_collection]
whois_collection = db[mongo_whois_collection]
geoip_collection = db[mongo_geoip_collection]
ipwhois_collection = db[mongo_ipwhois_collection]
user_collection = db[mongo_user_collection]

# Check if the user has provided a username and password for MongoDB
if mongo_user:
    client = pymongo.MongoClient(f"mongodb://{mongo_user}:{mongo_pass}@{mongo_host}:{mongo_port}/")
else:
    client = pymongo.MongoClient(f"mongodb://{mongo_host}:{mongo_port}/")

app = FastAPI(
    title="My API with WebSocket Documentation",
    description="""
    ## WebSocket Endpoints

    This API also includes WebSocket endpoints:

    - **/ws**: Main WebSocket endpoint for real-time communication.

    ### Usage
    To connect, use the WebSocket protocol: `ws://your-domain.com/ws`
    """,
    version="1.0.0"
)

# Just to show that the .env file is read correctly
# This configuration is not valid if uvicorn is run manually. 
# The variables HTTP_IP and HTTP_PORT is intended for use in a startup script (app_start.py)
print(f"Starting server at {HTTP_IP}:{HTTP_PORT}")

# SQLite database initialization. 
# This will be removed in a future version as we are migrating to MongoDB
print("Initiating database")
conn = sqlite3.connect('geoip.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS geoip (
    ip TEXT PRIMARY KEY,
    country TEXT,
    city TEXT,
    region TEXT,
    org TEXT,
    timezone TEXT,
    postal TEXT,
    latitude REAL,
    longitude REAL
)''')
conn.commit()

# This will be removed in a future version as we are migrating to MongoDB
c.execute('''
    CREATE TABLE IF NOT EXISTS whois_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_timestamp TEXT NOT NULL,
        domain_name TEXT,
        registrar TEXT,
        whois_server TEXT,
        updated_date TEXT,
        creation_date TEXT,
        expiration_date TEXT,
        name_servers TEXT,
        status TEXT,
        emails TEXT,
        dnssec TEXT,
        name TEXT,
        org TEXT,
        address TEXT,
        city TEXT,
        state TEXT,
        registrant_postal_code TEXT,
        country TEXT
    )
''')
# Delete the whois table
# c.execute('DROP TABLE whois_results')
conn.commit()

# Create a table for storing connection information
# This will be removed in a future version as we are migrating to MongoDB
c.execute('''
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        source_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER
    )
''')
conn.commit()


active_connections = []


# ip_cache = TTLCache(maxsize=1000, ttl=3600)  # Cache med 1000 poster og 1 time TTL (Time To Live)
ip_cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
# Read database into cache
# TODO: Read from MongoDB instead of SQLite
print("Reading database into cache...")

c.execute('SELECT * FROM geoip')
for row in c.fetchall():
    ip_cache[row[0]] = {
        'ip': row[0],
        'country': row[1],
        'city': row[2],
        'region': row[3],
        'org': row[4],
        'timezone': row[5],
        'postal': row[6],
        'latitude': row[7],
        'longitude': row[8]
    }

print(f"Cache initialized with {len(ip_cache)} entries")

# Function for storing WHOIS information in the SQLite database
# This will be removed in a future version as we are migrating to MongoDB
def store_domain_whois(domain_name):
    query_timestamp = datetime.now().isoformat()
    whois_info = {}

    try:
        # Do the WHOIS lookup for domain
        whois_info = whois.whois(domain_name)

        # Convert the dates to ISO format
        creation_date = whois_info.creation_date
        if isinstance(creation_date, datetime):
            creation_date = creation_date.isoformat()

        expiration_date = whois_info.expiration_date
        if isinstance(expiration_date, datetime):
            expiration_date = expiration_date.isoformat()

        updated_date = whois_info.updated_date
        if isinstance(updated_date, list):
            updated_date = ','.join([date.isoformat() if isinstance(date, datetime) else date for date in updated_date])
        elif isinstance(updated_date, datetime):
            updated_date = updated_date.isoformat()

        domain_name_str = ','.join(whois_info['domain_name']) if isinstance(whois_info.get('domain_name'), list) else whois_info.get('domain_name')
        name_servers_str = ','.join(whois_info['name_servers']) if isinstance(whois_info.get('name_servers'), list) else whois_info.get('name_servers')
        emails_str = ','.join(whois_info['emails']) if isinstance(whois_info.get('emails'), list) else whois_info.get('emails')

        # Store the WHOIS information in the SQLite database
        c.execute('''
            INSERT INTO whois_domains (
                query_timestamp, domain_name, registrar, whois_server, updated_date,
                creation_date, expiration_date, name_servers, status, emails,
                dnssec, name, org, address, city, state, registrant_postal_code, country
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            query_timestamp,
            domain_name_str,
            whois_info.registrar,
            whois_info.whois_server,
            updated_date,
            creation_date,
            expiration_date,
            name_servers_str,
            whois_info.status,
            emails_str,
            whois_info.dnssec,
            whois_info.name,
            whois_info.org,
            whois_info.address,
            whois_info.city,
            whois_info.state,
            whois_info.registrant_postal_code,
            whois_info.country
        ))
        conn.commit()

        print(f"WHOIS data for {domain_name} saved successfully.")
    except Exception as e:
        print(f"Error occurred: {e}")

    return whois_info


async def get_geoip_info(ip, nocache=False):
    if not nocache and ip in ip_cache:
        logging.info(f"\033[92mCache hit for IP: {ip}\033[0m")
        return ip_cache[ip]

    try:
        if not IPIFO_TOKEN:
            response = requests.get(f"https://ipinfo.io/{ip}").json()
        else:
            response = requests.get(f"https://ipinfo.io/{ip}?token={IPIFO_TOKEN}").json()
            logging.info(f"GeoIP info for {ip}: {response}")

        if 'loc' in response and response['loc']:
            latitude, longitude = response['loc'].split(',')
            geoip_info = {
                'ip': ip,
                'country': response.get('country'),
                'city': response.get('city'),
                'region': response.get('region'),
                'org': response.get('org'),
                'timezone': response.get('timezone'),
                'postal': response.get('postal'),
                'latitude': latitude,
                'longitude': longitude
            }
            if not nocache:
                ip_cache[ip] = geoip_info

                c.execute('INSERT OR REPLACE INTO geoip VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (
                    ip,
                    response.get('country'),
                    response.get('city'),
                    response.get('region'),
                    response.get('org'),
                    response.get('timezone'),
                    response.get('postal'),
                    latitude,
                    longitude
                ))
                conn.commit()

            # Write to MongoDB
            if not geoip_collection.find_one({"ip": ip}):
                geoip_collection.insert_one(geoip_info)

            # Remove the _id field before returning
            geoip_info.pop('_id', None)

            return geoip_info
        else:
            return {
                'ip': ip,
                'error': 'Location information not available'
            }
    except Exception as e:
        logging.error(f"Error fetching GeoIP info for {ip}: {e}")
        return {
            'ip': ip,
            'error': str(e)
        }


# Function for storing connection information in the database with latency measurement
def store_connection_info(source_ip, source_port, dest_ip, dest_port, timestamp=None):
    start_time = time.time()  # Start time messurement

    # Check for timestamp
    if not timestamp:
        timestamp = datetime.now().isoformat()
    c.execute('INSERT INTO connections (timestamp, source_ip, source_port, dest_ip, dest_port) VALUES (?, ?, ?, ?, ?)', (
        timestamp,
        source_ip,
        source_port,
        dest_ip,
        dest_port
    ))
    conn.commit()

    end_time = time.time()  # End time messurement

    # Calculate latency
    latency = end_time - start_time
    latency_times.append(latency)  # Add to latency list
    insert_times.append(end_time)  # Add to timestamp list

    return timestamp


# Store connection information in MongoDB
def store_connection_info_mongo(
    source_ip, source_port, dest_ip, dest_port,
    source_zone=None, dest_zone=None, fw_rule=None, fw_action=None,
    log_sender=None, log_proxy=None, timestamp=None
):


    # Select collection
    collection = db[mongo_fw_collection]
    if not timestamp:
        timestamp = datetime.now().isoformat()

    # Create the document
    document = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "source_zone": source_zone,
        "dest_zone": dest_zone,
        "fw_rule": fw_rule,
        "fw_action": fw_action,
        "fw_server": log_sender,
        "log_proxy": log_proxy
    }

    # Insert the document into the collection
    collection.insert_one(document)
    client.close()
    return timestamp


# Function for calculating average latency over the last 30 seconds
def get_latency_metrics():
    # Remove all inserts older than 30 seconds
    current_time = time.time()
    cutoff_time = current_time - 30

    # Remove old timestamps from the queue
    while insert_times and insert_times[0] < cutoff_time:
        insert_times.popleft()
        latency_times.popleft()

    # Calculate average latency and records per second
    if len(latency_times) > 0:
        avg_latency = sum(latency_times) / len(latency_times)
        records_per_second = len(latency_times) / 30.0
    else:
        avg_latency = 0
        records_per_second = 0

    return {
        'avg_latency': avg_latency,
        'records_per_second': records_per_second
    }


# Get top 10 connections from the database, and get GeoIP info for the source IP
# get all unique destination port numbers for each source IP as well.
# Example: One ip is listed 60 times, with the same destination port number each time. eg. 443
# If sort_by variable is set to 'source_ip', the function will return the top 10 source IP addresses
# if the sort_by variable is set to 'dest_port', the function will return the top 10 source ip 
# by the number of uniqe destination port numbers. The function must return the following:
# source_ip, count, geoip_info, unique_dest_ports, unique_dest_ports_count
# TODO: Migrate this function to MongoDB
async def get_top_connections(sort_by='source_ip'):
    top_connections = []
    if sort_by == 'source_ip':
        c.execute('''
            SELECT source_ip, COUNT(source_ip) as count FROM connections
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        for row in c.fetchall():
            source_ip = row[0]
            count = row[1]
            geoip_info = await get_geoip_info(source_ip)
            c.execute('''
                SELECT DISTINCT dest_port FROM connections
                WHERE source_ip = ?
            ''', (source_ip,))
            unique_dest_ports = [port[0] for port in c.fetchall()]
            unique_dest_ports_count = len(unique_dest_ports)
            top_connections.append({
                'source_ip': source_ip,
                'count': count,
                'geoip_info': geoip_info,
                'unique_dest_ports': unique_dest_ports,
                'unique_dest_ports_count': unique_dest_ports_count
            })
    elif sort_by == 'dest_port':
        c.execute('''
            SELECT source_ip, COUNT(DISTINCT dest_port) as count FROM connections
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        for row in c.fetchall():
            source_ip = row[0]
            count = row[1]
            geoip_info = await get_geoip_info(source_ip)
            c.execute('''
                SELECT DISTINCT dest_port FROM connections
                WHERE source_ip = ?
            ''', (source_ip,))
            unique_dest_ports = [port[0] for port in c.fetchall()]
            unique_dest_ports_count = len(unique_dest_ports)
            top_connections.append({
                'source_ip': source_ip,
                'count': count,
                'geoip_info': geoip_info,
                'unique_dest_ports': unique_dest_ports,
                'unique_dest_ports_count': unique_dest_ports_count
            })
    return top_connections


# Notify all connected WS-clients
async def notify_clients(message):
    for connection in active_connections:
        await connection.send_json(message)

# ----------------- Endpoints -----------------

# Default route to serve the index file
@app.get("/")
async def serve_index():
    return FileResponse("index_cyber.html")

# To prevent 404 errors when favicon is requested
@app.get("/favicon.ico")
async def favicon():
    return FileResponse("favicon.ico")

# To serve static files like CSS and JavaScript


# Flag icons.
# Subfolders for different sizes: 100, 250 and 1000
# Example: /static/flags/png100px/af.png
@app.get("/static/flags/png100px/{filename}")
async def serve_static(filename):
    return FileResponse(f"country-flags-main/png100px/{filename}")

@app.get("/static/flags/png250px/{filename}")
async def serve_static(filename):
    return FileResponse(f"country-flags-main/png250px/{filename}")

@app.get("/static/flags/png1000px/{filename}")
async def serve_static(filename):
    return FileResponse(f"country-flags-main/png1000px/{filename}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    logging.info('WebSocket connection accepted')
    try:
        while True:
            try:
                ip = await websocket.receive_text()
                logging.info(f"Received IP: {ip}")
                geoip_info = await get_geoip_info(ip)
                logging.info(f"Sending GeoIP info: {geoip_info}")
                await notify_clients(geoip_info)
            except WebSocketDisconnect:
                logging.info("WebSocket connection closed by client")
                break
    except Exception as e:
        logging.error(f"WebSocket connection error: {e}")
    finally:
        active_connections.remove(websocket)
        try:
            await websocket.close()
        except Exception as e:
            logging.error(f"Error closing WebSocket connection: {e}")
        logging.info('WebSocket connection closed')


# This endpoint is deprecated and will be removed in a future version
@app.post("/ip")
async def receive_ip(ip: str, request: Request, nocache: Optional[bool] = False):
    logging.info(f"Received IP via REST: {ip} with nocache={nocache}")

    geoip_info = await get_geoip_info(ip, nocache=nocache)
    if 'error' in geoip_info:
        raise HTTPException(status_code=400, detail=geoip_info['error'])
    await notify_clients(geoip_info)
    return geoip_info


@app.post("/connection")
async def receive_connection_info(
    source_ip: str,
    source_port: int,
    dest_ip: str,
    dest_port: int,
    request: Request,
    source_zone: Optional[str] = None,
    dest_zone: Optional[str] = None,
    fw_rule: Optional[str] = None,
    fw_action: Optional[str] = None,  # Allow, Deny, Reject, Drop, Log, TarPit, dst-nat, src-nat, etc.
    nocache: Optional[bool] = False,
    log_sender: Optional[str] = None,
    log_proxy: Optional[str] = None,
    in_interface: Optional[str] = None,
    out_interface: Optional[str] = None,
    src_mac: Optional[str] = None,
    protocol: Optional[str] = None,
    connection_state: Optional[str] = None,
    packet_mark: Optional[str] = None
):
    logging.info(f"Received connection info via REST: {source_ip}:{source_port} -> {dest_ip}:{dest_port} with nocache={nocache}")
    # Store the IP address in the database using the store_connection_info
    timestamp = datetime.now().isoformat()
    store_ip_sqlite = store_connection_info(source_ip, source_port, dest_ip, dest_port, timestamp=timestamp)
    print(f"Connection info stored in sqlite with timestamp: {store_ip_sqlite}")

    # Store the connection info in MongoDB
    store_ip_mongo = store_connection_info_mongo(
        source_ip, source_port, dest_ip, dest_port,
        source_zone=source_zone, dest_zone=dest_zone,
        fw_rule=fw_rule, fw_action=fw_action,
        log_sender=log_sender, log_proxy=log_proxy,
        timestamp=timestamp
    )
    print(f"Connection info stored in MongoDB with timestamp: {store_ip_mongo}")

    geoip_info = await get_geoip_info(source_ip, nocache=nocache)
    if 'error' in geoip_info:
        raise HTTPException(status_code=400, detail=geoip_info['error'])

    connection_info = {
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "geoip_info": geoip_info
    }

    await notify_clients(connection_info)
    # await notify_clients(geoip_info)
    return connection_info


@app.get("/api/ip/cache")
async def get_cache():
    return [{ip: data} for ip, data in ip_cache.items()]


@app.get("/api/ip/cache/{ip}")
async def get_cache_ip(ip: str):
    if ip in ip_cache:
        return {ip: ip_cache[ip]}
    else:
        raise HTTPException(status_code=404, detail="IP not found in cache")


# Endpoint for getting top 10 connections
@app.get("/api/connections/top/{sort_by}")
async def get_top_connections_api(sort_by: str):
    return await get_top_connections(sort_by=sort_by)


# WHOIS lookup. Can be domain name, AS number or IP address.
# Use the python-whois library to perform the lookup
# Log the results to database with timestamp
@app.get("/api/whois/{query}")
async def get_whois(query: str):
    print(f"WHOIS lookup for {query}")
    whois_info = {}

    try:
        # Prøv å tolke query som en IP-adresse
        ip = ipaddress.ip_address(query)
        try:
            ipwhois = IPWhois(str(ip))
            whois_info = ipwhois.lookup_rdap()
        except Exception as e:
            print(f"Error occurred with IP WHOIS lookup: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    except ValueError:
        # Hvis det ikke er en IP-adresse, antas det å være et domenenavn
        try:
            # whois_info = whois.whois(query)
            whois_info = store_domain_whois(query)
        except Exception as e:
            print(f"Error occurred with domain WHOIS lookup: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    return whois_info

# Endpoint for listing active WebSocket connections
@app.get("/api/connections")
async def get_ws_connections():
    return [str(connection.client) for connection in active_connections]


# Endpoint for getting latency metrics
@app.get("/api/metrics")
async def get_metrics():
    metrics = get_latency_metrics()
    return metrics


# Serve the geojson file
# This file contains the geometry for all countries in the world
@app.get("/static/geojson/countries.geojson")
async def serve_geojson():
    return FileResponse("geojson/countries.geojson")

# Endpoint for looking up services py port number
# We import the csv-file with port numbers and services (service-names-port-numbers.csv)
# and return the service name for the given port number
# Example: /service/80
# Returns: {"port": 80, "service": "http"}
# If the port number is not found,
# we return an error message and if we are getting multiple results,
# we return a list of services

# File description: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
# File: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
@app.get("/service/{port}")
async def get_service(port: int):
    services = []
    try:
        with open('service-names-port-numbers.csv', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                port_range = row['Port Number'].strip().split('-')
                # Check if port_range[0] is a valid integer
                if port_range[0].isdigit():
                    start_port = int(port_range[0])
                    # If it is a range, handle it
                    if len(port_range) == 2 and port_range[1].isdigit():
                        end_port = int(port_range[1])
                        if start_port <= port <= end_port:
                            services.append({
                                "service_name": row['Service Name'],
                                "description": row['Description'],
                                "transport_protocol": row['Transport Protocol'],
                                "assignee": row['Assignee'],
                                "contact": row['Contact'],
                                "reference": row['Reference'],
                                "service_code": row['Service Code'],
                                "unauthorized_use_reported": row['Unauthorized Use Reported'],
                                "assignment_notes": row['Assignment Notes']
                            })
                    elif len(port_range) == 1:
                        if start_port == port:
                            services.append({
                                "service_name": row['Service Name'],
                                "description": row['Description'],
                                "transport_protocol": row['Transport Protocol'],
                                "assignee": row['Assignee'],
                                "contact": row['Contact'],
                                "reference": row['Reference'],
                                "service_code": row['Service Code'],
                                "unauthorized_use_reported": row['Unauthorized Use Reported'],
                                "assignment_notes": row['Assignment Notes']
                            })

        if len(services) == 1:
            return {"port": port, "service": services[0]}
        elif len(services) > 1:
            return {"port": port, "services": services}
        else:
            return {"error": "Port number not found"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Migration of data from SQLite to MongoDB

# Migrate geoip_collection data from SQLite to MongoDB
def migrate_geoip_data():
    # Empty the collection in MongoDB
    geoip_collection.delete_many({})

    # Get all records from the SQLite table 'geoip'
    c.execute("SELECT * FROM geoip")
    rows = c.fetchall()

    # Print the number of rows
    print(f"Found {len(rows)} records in SQLite.")
    # Insert records into MongoDB
    for row in rows:
        # Extract fields from the SQLite row
        ip, country, city, region, org, timezone, postal, latitude, longitude = row
        print(f"Inserting record with ip: {ip}")
        # Check if there is already a document with the same IP in MongoDB
        if not geoip_collection.find_one({"ip": ip}):
            geoip_collection.insert_one({
                "ip": ip,
                "country": country,
                "city": city,
                "region": region,
                "org": org,
                "timezone": timezone,
                "postal": postal,
                "latitude": latitude,
                "longitude": longitude
            })
        else:
            print(f"Duplicate found, skipping IP: {ip}")

    print(f"Migration complete. Inserted {geoip_collection.count_documents({})} records into MongoDB.")


# Migrate firewall logs from SQLite to MongoDB
def migrate_firewall_data():
    # Empty the collection in MongoDB
    firewall_collection.delete_many({})

    # Get all records from the SQLite table 'connections'
    c.execute("SELECT * FROM connections")
    rows = c.fetchall()

    # Print the number of rows
    print(f"Found {len(rows)} records in SQLite.")
    # Insert records into MongoDB
    for row in rows:
        # Extract fields from the SQLite row
        id, timestamp, source_ip, source_port, dest_ip, dest_port = row
        print(f"Inserting record with id: {id}")
        # Check if there is already a document with the same timestamp in MongoDB
        if not firewall_collection.find_one({"timestamp": timestamp}):
            firewall_collection.insert_one({
                "timestamp": timestamp,
                "source_ip": source_ip,
                "source_port": source_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port
            })
        else:
            print(f"Duplicate found, skipping timestamp: {timestamp}")

    print(f"Migration complete. Inserted {firewall_collection.count_documents({})} records into MongoDB.")


# Migrate data from SQLite to MongoDB. 
# This should be done only if you have data in the SQLite database, and not in MongoDB
# 
# migrate_firewall_data()
# migrate_geoip_data()