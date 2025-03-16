from sqlalchemy import Column, String, Text, Enum as SQLAlchemyEnum, DateTime, func
from api.db.database import Base
from uuid_extensions import uuid7
import enum  # Import Python's enum module

# Enum for Service Types
class ServiceType(enum.Enum):  # Use Python's enum.Enum
    PATHOLOGY = "pathology"
    HISTOLOGY = "histology"
    AUTOPSY = "autopsy"
    RESEARCH = "research"
    CYTOLOGY = "cytology"
    CONSULTATION = "consultation"

# Contact Table Model
class ContactRequest(Base):
    __tablename__ = "orders"

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid7()))
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    phone = Column(String, nullable=False)
    service = Column(SQLAlchemyEnum(ServiceType), nullable=False)  # Use SQLAlchemy's Enum
    message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
