import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Laste inn miljøvariablene fra .env-filen
load_dotenv()

MONGO_HOST = os.getenv("MONGO_HOST")
MONGO_PORT = int(os.getenv("MONGO_PORT"))
MONGO_DB = os.getenv("MONGO_DB", "testdb")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "testcollection")

# Koble til MongoDB-serveren
client = MongoClient(MONGO_HOST, MONGO_PORT)
db = client[MONGO_DB]
collection = db[MONGO_COLLECTION]


def test_mongodb():
    # 1. Skriv data til MongoDB
    test_data = {"name": "John Doe", "email": "john.doe@example.com", "age": 30}
    insert_result = collection.insert_one(test_data)
    print(f"Data inserted with _id: {insert_result.inserted_id}")

    # 2. Les data fra MongoDB
    retrieved_data = collection.find_one({"_id": insert_result.inserted_id})
    print("Retrieved data from MongoDB:", retrieved_data)

    # 3. Slett data fra MongoDB
    delete_result = collection.delete_one({"_id": insert_result.inserted_id})
    if delete_result.deleted_count > 0:
        print(f"Data with _id {insert_result.inserted_id} was deleted successfully")
    else:
        print("No data found to delete")


if __name__ == "__main__":
    test_mongodb()
