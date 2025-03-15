from datetime import timedelta, datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status, Body, HTTPException
from fastapi.background import BackgroundTasks
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from api.db.database import get_db
from api.utils.settings import settings
from api.v1.schemas.user import CreateUser
from api.v1.schemas.auth import LoginRequest
from api.v1.services.user import user_service
from api.utils.response import auth_response, success_response
    

auth = APIRouter(prefix="/auth", tags=["Authentication"])

@auth.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    http_request: Request,
    user_schema: CreateUser,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Parameters:
    - request (CreateUser): An object containing the details of the new user.
    - db (Session): A database session object.

    Returns:
    - An object containing the details of the newly created user.

    Raises:
    - HTTPException: If a user with the same phone number or email already exists.

    The function first checks if a user with the same phone number or email already exists in the database.
    If such a user is found, it raises an HTTPException with a status code of 409 (Conflict)
    and a message indicating the existence of the duplicate user.

    If no such user is found, the function hashes the password using the `auth.get_password_hash`
    function and creates a new `User` object with the provided details.
    It then adds the new user to the database session and returns the newly created user as an object.
    Note that password has to be at least 8 characters and include alphabets, numbers, and a special character.
    """
    user = await user_service.create_user(user_schema, db)
    access_token = user_service.create_access_token(user.id)
    refresh_token = user_service.create_refresh_token(user_id=user.id)

    background_tasks.add_task(
        user_service.send_verification_mail,
        user_schema.email,
        http_request,
        user_schema,
    )

    response = auth_response(
        status_code=201,
        message="User created successfully",
        access_token=access_token,
        data={
            "user": jsonable_encoder(
                user,
                exclude=["password", "is_deleted", "is_verified", "updated_at"]
            ),
        },
    )

    # Set cookies for c and refresh tokens
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        max_age=int(
            timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()
        ),
        expires=(datetime.now(timezone.utc)
                 + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
        path="/",
        domain=settings.COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="none",
    )
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {refresh_token}",
        max_age=int(
            timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()
        ),
        expires=(datetime.now(timezone.utc)
                 + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
        path="/",
        domain=settings.COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="none",
    )

    return response


# @auth.get("/verify-email")
# def verify_email(token: str, db: Session = Depends(get_db)):
#     '''Endpoint to verify email'''
#     try:
#         return user_service.verify_user_email(token, db)
#     except ExpiredSignatureError:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Verification link expired"
#             )
        
#     except JWTError:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Invalid token"
#             )

# @auth.post("/resend_verification_email")
# def resend_verification_email(request: Request, data: UserEmailSender, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
#     """Resends the email verification link"""
#     email = data.email
#     print(email)
#     user = user_service.user_to_verify(email, db)
#     verification_token = user_service.create_verification_token(user.id)
#     base_url = str(request.base_url).strip("/")
#     verification_link = f"{base_url}/api/v1/auth/verify-email?token={verification_token}"
#     cta_link = 'https://anchor-python.teams.hng.tech/about-us'

#     background_tasks.add_task(
#         send_email,
#         recipient=email,
#         template_name='welcome.html',
#         subject='Welcome to HNG Boilerplate, Verify Your Email below',
#         context={
#             'first_name': user.first_name,
#             'last_name': user.last_name,
#             'verification_link': verification_link,
#             'cta_link': cta_link
#         }
#     )

#     return {
#         "status": "success",
#         "status_code": 200,
#         "message": "Verification email sent successfully"
#     }
 


@auth.post("/login")
def login(
    credentials: LoginRequest = Body(...),
    db: Session = Depends(get_db),
):
    """
    Custom Login Endpoint.

    This endpoint authenticates a user using JSON input with an email and password.
    If the credentials are valid, it generates an access token and sets it as a cookie.

    Parameters:
    - response (Response): The FastAPI response object.
    - credentials (LoginRequest): A Pydantic model containing "email" and "password".
    - db (Session): The database session.

    Request Body:
    - email (str): The user's email address.
    - password (str): The user's password.

    Returns:
    - Token: A Token object containing the access token and token type.

    Raises:
    - HTTPException: If the email or password is incorrect.
    """
    email = credentials.email.strip().lower()
    password = credentials.password

    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required."
        )

    user = user_service.authenticate_user(email, password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials."
        )

    access_token = user_service.create_access_token(user.id)
    refresh_token = user_service.create_refresh_token(user_id=user.id)

    user_orgs = set(user.owned_organisations)
    organisations = []
    for org in user_orgs:
        organisations.append(org)
        org_campaign = []
        for campaign in org.campaigns:
            org_campaign.append(campaign)

    response = auth_response(
        status_code=status.HTTP_200_OK,
        message="User logged in successfully",
        access_token=access_token,
        data={
            "user": jsonable_encoder(
                user, exclude=["password", "is_deleted",
                               "is_verified", "updated_at"]
            ),

        },
    )
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        max_age=int(
            timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()
        ),
        expires=(datetime.now(timezone.utc)
                 + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
        path="/",
        domain=settings.COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="none",
    )
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {refresh_token}",
        max_age=int(
            timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()
        ),
        expires=(datetime.now(timezone.utc)
                 + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
        path="/",
        domain=settings.COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="none",
    )

    return response


@auth.post("/logout")
def logout():
    """
    Logout endpoint.

    This endpoint clears the access cookies and returns a success message.

    Parameters:
    - response (Response): The FastAPI response object.

    Returns:
    - dict: A dictionary containing a success message.
    """   
    
    response = success_response(
        status_code=status.HTTP_200_OK, message="User logged out successfully"
    )

    user_service.delete_access_cookies(response)

    return response

