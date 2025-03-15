""" User data model
"""

from sqlalchemy import Column, String, text, Boolean, Index
from sqlalchemy.orm import relationship
from api.v1.models.base_model import BaseTableModel


class User(BaseTableModel):
    __tablename__ = "users"

    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=True)
    username = Column(String, nullable=True)
