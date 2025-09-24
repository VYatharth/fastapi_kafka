import os
from contextlib import asynccontextmanager
from kafka import KafkaConsumer
from dotenv import load_dotenv
from fastapi import FastAPI
import json
import asyncio

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = [os.environ.get("KAFKA_SERVERS_URL")]
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC")
CONSUMER_ID = os.environ.get("CONSUMER_ID")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup event
    print("Starting up...")


    try:
        app.state.kafka_consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            # Start reading at the earliest message if no offset is committed for the group
            auto_offset_reset='earliest',
            # Enable automatic offset committing
            enable_auto_commit=True,
            # Specify a consumer group (important for distributed consumption)
            group_id=CONSUMER_ID,
        )

        yield

        # Shutdown event
        print("Shutting down...")


    finally:    
        if app.state.kafka_consumer and not app.state.kafka_consumer._closed:
            app.state.kafka_consumer.close()


stop_polling_event = asyncio.Event()

async def poll_for_messages(app: FastAPI):
    """Asynchronously consumes messages from Kafka."""
    try:
        while not stop_polling_event.is_set():
                messages = app.state.kafka_consumer.poll(5000, max_records=100)
                if messages:
                    for topic_partition, records in messages.items():
                        for record in records:
                            print(f"Received message: {record.value} from topic: {record.topic}, partition: {record.partition}, offset: {record.offset}")
                await asyncio.sleep(0.1)  # Small delay to prevent tight loop
    except Exception as e:
        print(f"Error while consuming messages: {e}")
        stop_kafka_polling()
   

polling_tasks = []

def stop_kafka_polling():
    stop_polling_event.set()
    if polling_tasks:
        polling_tasks.pop()
        

app = FastAPI(lifespan=lifespan)

@app.get("/start-polling")
async def start_polling():
    if not polling_tasks:
        stop_polling_event.clear()
        polling_tasks.append(asyncio.create_task(poll_for_messages(app)))

        return "Polling started"
    
    return "Already polling"


@app.get("/stop-polling")
async def stop_polling():
    stop_kafka_polling()

    return "Polling stopped"


@app.get("/health")
async def health_check():
    return {"status": "ok"}
