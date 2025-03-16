from pydantic import BaseModel

class OrderSchema(BaseModel):
    name: str
    email:str
    phone: str
    service:str
    message: str

