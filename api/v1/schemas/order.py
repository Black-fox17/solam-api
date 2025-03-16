from pydantic import BaseModel
from api.v1.models.order import ServiceType  # Import the Enum

class OrderSchema(BaseModel):
    name: str
    email: str
    phone: str
    service: ServiceType  # Change str → ServiceType
    message: str
