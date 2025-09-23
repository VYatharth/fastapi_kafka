import json
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from kafka import KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic
from producer_app.models import KafkaMessage

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_SERVERS_URL")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC")
PRODUCER_ID = os.environ.get("PRODUCER_ID")
ADMIN_CLIENT_ID = os.environ.get("ADMIN_CLIENT_ID")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup event
    print("Starting up...")

    # create Kafka topic if it doesn't exist
    admin_client = KafkaAdminClient(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, 
        client_id=ADMIN_CLIENT_ID
    )

    try:
        if KAFKA_TOPIC not in admin_client.list_topics():
            topic_list = [NewTopic(name=KAFKA_TOPIC, num_partitions=1, replication_factor=1)]
            admin_client.create_topics(new_topics=topic_list, validate_only=False)
            print(f"Topic '{KAFKA_TOPIC}' created successfully.")
    except Exception as e:
        print(f"Error creating topic: {e}")
        raise HTTPException(status_code=500, detail="Error while creating topic in Kafka")
    finally:
        admin_client.close()


    try:
        # create producer
        app.state.kafka_producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            client_id=PRODUCER_ID,
        )

        yield

        # Shutdown event
        print("Shutting down...")

        if app.state.kafka_producer:
            app.state.kafka_producer.flush()

    finally:    
        if app.state.kafka_producer:
            app.state.kafka_producer.close()

def send_kafka_message(app: FastAPI, message: KafkaMessage):
    try:
        app.state.kafka_producer.send(KAFKA_TOPIC, message.model_dump())
    except Exception as e:
        print(f"Error sending message to Kafka: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message to Kafka")


app = FastAPI(lifespan=lifespan)


@app.post("/produce")
async def produce_message(message: str):
    send_kafka_message(app, KafkaMessage(content=message))

    return {"status": "Message sent to Kafka"}


@app.get("/health")
async def health_check():
    return {"status": "ok"}
