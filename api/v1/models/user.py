""" User data model
"""

from sqlalchemy import Column, String, text, Boolean, Index
from sqlalchemy.orm import relationship
from api.v1.models.associations import user_organisation_association
from api.v1.models.permissions.user_org_role import user_organisation_roles
from api.v1.models.base_model import BaseTableModel


class User(BaseTableModel):
    __tablename__ = "users"

    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    is_active = Column(Boolean, server_default=text("true"))
    is_superadmin = Column(Boolean, server_default=text("false"))
    is_deleted = Column(Boolean, server_default=text("false"))
    is_verified = Column(Boolean, server_default=text("false"))

    # Defining indexes for frequently queried columns
    __table_args__ = (
        Index('ix_users_email', 'email'),
        Index('ix_users_is_active', 'is_active'),
        Index('ix_users_is_deleted', 'is_deleted'),
        Index('ix_users_is_verified', 'is_verified'),
        Index('ix_users_is_superadmin', 'is_superadmin'),
        Index('ix_users_first_name_last_name', 'first_name', 'last_name'),
    )
