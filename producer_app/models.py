from pydantic import BaseModel, Field

class KafkaMessage(BaseModel):
    content: str = Field(min_length=1, max_length=280)