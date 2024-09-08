# Log Aggregation and Analysis with FastAPI, MongoDB, and Pydantic

## The following is intended to be a Roadmap to future versions of this project.

This project provides a generic approach for handling log data from various sources such as firewalls, NGINX, Postfix, SSH (auth.log), and HTTP servers. By leveraging **FastAPI**, **MongoDB**, and **Pydantic** for data validation, the project ensures structured and consistent log handling, which is useful for analyzing traffic patterns, monitoring server activity, and investigating potential attacks.

## Features
- **FastAPI** framework for handling REST API requests.
- **MongoDB** for storing and querying logs from multiple sources.
- **Pydantic** models for validating and ensuring consistent log structure.
- **Support for multiple log categories** including firewall logs, NGINX logs, Postfix logs, and more.
- **WebSocket integration** to send real-time updates to connected clients.

## Setup Instructions

### Prerequisites
- **Python 3.8+**
- **MongoDB**
- **FastAPI** framework
- **Pydantic** for data validation

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo-name.git
   cd your-repo-name

2. Install the required dependencies:
    ````bash
    pip install -r requirements.txt

3. Configure your MongoDB settings in the .env file:
    ````env
    MONGO_HOST = "192.168.0.100"
    MONGO_PORT = 27017
    MONGO_USER = "root"
    MONGO_PASS = "testpass"
    MONGO_DB = "cyber_analysis"

    # Log collections
    MONGO_FW_COLLECTION = "firewall_logs"
    MONGO_NGINX_COLLECTION = "nginx_logs"
    MONGO_POSTFIX_COLLECTION = "postfix_logs"
    MONGO_AUTH_COLLECTION = "auth_logs"
    MONGO_HTTPD_COLLECTION = "httpd_logs"

4. Run the FastAPI server:
    ````bash
    uvicorn main:app --reload

### Handling Different Log Categories

    This project introduces a generic /log endpoint that processes logs based on a specified log_category. Each log category, such as firewall, nginx, postfix, etc., is processed according to its own schema. We use Pydantic models to validate and structure incoming data for each category, ensuring data consistency.

#### The following log categories are supported:

    - Firewall Logs
    - NGINX Logs
    - Postfix Logs
    - SSH Auth Logs
    - HTTPD Logs

### Generic Log Endpoint

    The /log endpoint processes different log categories by mapping them to their respective MongoDB collections and validating the payload using Pydantic models:
    ````python
    @app.post("/log")
    async def receive_log(
        log_category: str,
        payload: dict  # Incoming log data
    ):
        # Map log categories to MongoDB collections
        collection_map = {
            "firewall": firewall_collection,
            "nginx": nginx_collection,
            "postfix": postfix_collection,
            "auth": auth_collection,
            "httpd": httpd_collection,
        }

        if log_category in collection_map:
            collection = collection_map[log_category]

            # Validate log data using Pydantic models
            if log_category in log_model_map:
                LogModel = log_model_map[log_category]
                try:
                    validated_data = LogModel(**payload).dict()
                    collection.insert_one(validated_data)
                    return {"status": f"{log_category} log processed"}
                except Exception as e:
                    raise HTTPException(status_code=400, detail=str(e))
            else:
                raise HTTPException(status_code=400, detail="No model for log category")
        else:
            raise HTTPException(status_code=400, detail="Unknown log category")
    ````

### Pydantic Models

    Pydantic is used to define and validate the structure of incoming log data. This ensures consistency across different log categories.

    For example, the model for a Firewall Log looks like this:
    ````python
    class FirewallLog(BaseModel):
        source_ip: str
        source_port: int
        dest_ip: str
        dest_port: int
        protocol: Optional[str] = None
        action: Optional[str] = None
        fw_rule: Optional[str] = None
        connection_state: Optional[str] = None
        in_interface: Optional[str] = None
        out_interface: Optional[str] = None
        timestamp: datetime
    ````

Similar models are defined for NGINX, Postfix, Auth, and HTTPD logs.

### Real-Time Updates with WebSockets

    The project also uses WebSockets to send real-time log updates to connected clients. This allows for live tracking of incoming traffic and potential attacks on servers.

    ````python
    # Sending real-time GeoIP info to WebSocket clients
    await notify_clients(connection_info)
    ````

### Extensibility

    This project is designed to be extensible. If you want to add support for new log categories, simply:

    1. Define a new Pydantic model for the log category.
    2. Add the model to the log_model_map.
    3. Update the MongoDB collection map to store the new log category in a different collection.

### Future Enhancements

    - CRUD operations: To fully support create, read, update, and delete (CRUD) operations for MongoDB collections, additional routes can be created for each log category.
    - Separate Routers: The current project is a working proof of concept but should eventually separate log categories into their own routers.
    - Advanced Reporting and Analysis: Adding support for more detailed reporting and analysis tools, such as graphical visualizations of logs.

### Real-World Use Case

    While this project is designed to process server logs for cybersecurity purposes, the same methods can be applied to e-commerce platforms for visualizing customer activity, identifying popular regions, and analyzing buying trends.

### Acknowledgements

    This project was built with love and the help of ChatGPT and GitHub Copilot. It serves as a prototype for real-time log analysis, but improvements such as proper routing, schemas, and enhanced MongoDB queries are still needed for full production readiness.

