import os
from contextlib import asynccontextmanager

from aiokafka import AIOKafkaProducer
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_SERVERS_URL")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC")
PRODUCER_ID = os.environ.get("PRODUCER_ID")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup event
    print("Starting up...")
    app.state.kafka_producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS)
    await app.state.kafka_producer.start()

    yield

    # Shutdown event
    print("Shutting down...")
    await app.state.kafka_producer.stop()
    
app = FastAPI(lifespan=lifespan)

@app.post("/produce")
async def produce_message(message: str):
    try:
        await app.state.kafka_producer.send_and_wait(KAFKA_TOPIC, message.encode("utf-8"))
    except Exception as e:
        print(f"Error sending message to Kafka: {e}")
        raise HTTPException(status_code=500, detail='Failed to send message to Kafka')

    return {"status": "Message sent to Kafka"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}