from typing import Optional, Annotated, Literal
from pydantic import BaseModel, EmailStr, StringConstraints, model_validator
from pydantic import BaseModel, field_validator, ValidationInfo
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator, ValidationError
from email_validator import validate_email, EmailNotValidError


class CreateUser(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, email: str, info: ValidationInfo):
        """
        Validates email format and checks if both email and password are empty.
        """
        email = email.replace(" ", "")
        password = info.data.get("password")

        if not email and not password:
            raise HTTPException(
                status_code=400, detail="Email or Password cannot be empty.")

        if not email:
            raise HTTPException(
                status_code=400, detail="Email cannot be empty.")

        try:
            validate_email(email, check_deliverability=True)
            return email
        except EmailNotValidError as e:
            raise ValueError(f"Invalid email: {e}")

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str):
        """
        Validates that the password is at least 4 characters long.
        """
        password = password.replace(" ", "")
        if not password:
            raise HTTPException(
                status_code=400, detail="Password cannot be empty.")

        if len(password) < 4:
            raise ValueError("Password must be at least 4 characters long.")

        return password


class TokenData(BaseModel):
    """Schema to structure token data"""

    id: Optional[str]
