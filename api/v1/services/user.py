# from fastapi import HTTPException, status
# from api.v1.schemas.user import TokenData
# from api.v1.models import User, Organisation
from sqlalchemy.orm import Session
from api.v1.schemas.user import CreateUser
# from api.v1.models.permissions.permission import Permission
# from typing import List, Any, Optional, Annotated

from datetime import datetime, timedelta, timezone
# from fastapi.security import OAuth2PasswordBearer

# from fastapi import Depends, HTTPException, Request, Response, status
from itsdangerous import URLSafeTimedSerializer
from jose import JWTError, jwt
from passlib.context import CryptContext
# from pydantic import EmailStr
from starlette import status
from sqlalchemy.orm import Session

from api.utils.settings import settings
from api.utils.cookies import OAuth2PasswordBearerWithCookie
from api.db.database import get_db
from api.v1.models.user import User
# from api.utils.email import Email, SendGridEmail
# from api.utils.db_validators import check_model_existence
# from api.v1.schemas.user import TokenData
# from api.v1.schemas.campaign import CampaignCreate
# from functools import wraps
from fastapi import HTTPException
from fastapi import Depends, Request
from sqlalchemy.orm import Session

# verification_serializer = URLSafeTimedSerializer(
#     settings.SECRET_KEY, salt="verification"
# )
oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/api/v1/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserService:
    async def create_user(self, schema: CreateUser, db: Session) -> User:
        ""

        if db.query(User).filter(User.email == schema.email).first():
            raise HTTPException(
                status_code=400,
                detail="User with this email already exists",
            )

        schema.password = self.hash_password(password=schema.password)

        user = User(**schema.model_dump())

        db.add(user)
        db.commit()
        db.refresh(user)

        return user
    
    def create_refresh_token(self, user_id: str) -> str:
        """Function to create access token"""

        expires = datetime.now(timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_EXPIRY
        )
        data = {"user_id": user_id, "exp": expires, "type": "refresh"}
        encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        return encoded_jwt
    
    def create_access_token(self, user_id: str) -> str:
        """Function to create access token"""

        expires = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        data = {"user_id": user_id, "exp": expires, "type": "access"}
        encoded_jwt = jwt.encode(data, settings.SECRET_KEY, settings.ALGORITHM)
        return encoded_jwt
    def hash_password(self, password: str) -> str:
        """Function to hash a password"""

        hashed_password = pwd_context.hash(secret=password)
        return hashed_password
    
    def authenticate_user(
        self,
        email: str,
        password: str,
        db: Session = Depends(get_db),
    ) -> User | bool:
        """
        Authenticate a user based on their email and password.

        Parameters:
        email (str): The email of the user to be authenticated.
        password (str): The password of the user to be authenticated.
        db (Session, optional): The database session object to be used for querying the user. If not provided, the function will use the session object provided by the load function.

        Returns:
        Union[User, bool]: If the user is authenticated and exists in the database, the User object is returned. If the user does not exist or the password is incorrect, False is returned.

        Note:
        This function queries the database to find the user with the provided email.
        It then verifies the password using the verify_password function.
        If the user is authenticated, the User object is returned. Otherwise, False is returned.
        """
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=404,
                detail=[{"msg": "User not found"}],
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not self.verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=[{"msg": "Incorrect email or password"}],
                headers={"WWW-Authenticate": "Bearer"},
            )
        print(user)
        return user
    def verify_password(self, password: str, hash: str) -> bool:
        """Function to verify a hashed password"""

        return pwd_context.verify(secret=password, hash=hash)\
        
    def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        """
        Retrieve the current user based on the provided access token.

        Parameters:
        token (str, optional): The access token to be used for authentication.
        If not provided, the function will use the token provided by the OAuth2PasswordBearerWithCookie.
        db (Session, optional): The database session object to be used for querying the user.
        If not provided, the function will use the session object provided by the load function.

        Returns:
        User: The User object representing the current user.

        Raises:
        HTTPException: If the access token is not valid or the user does not exist in the database.

        Note:
        This function decodes the access token using the JWT library, retrieves the username from the payload,
        and queries the database to find the corresponding user.
        If the access token is not valid or the user does not exist,
        an HTTPException is raised with appropriate error details.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id: str = payload.get("user_id")
            if user_id is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception
        return user

#     def get_user_by_id(self, db: Session, request: Request, id: str):
#         """Fetches a user by their id"""
#         authorization: str = request.headers.get("Authorization")
#         if not authorization or not authorization.startswith("Bearer "):
#             raise HTTPException(
#                 status_code=401, detail="Invalid or missing authorization token")

#         access_token = authorization.split("Bearer ")[1]

#         token = self.verify_access_token(access_token, HTTPException(
#             status_code=401,
#             detail="Could not validate credentials",
#             headers={"WWW-Authenticate": "Bearer"},
#         ))

#         user = check_model_existence(db, User, token.id)
#         check_user = check_model_existence(db, User, id)
#         if not user.is_admin and not check_user.is_active:
#             raise HTTPException(
#                 status_code=404,
#                 detail="User does not exist",
#             )

#         if not user.is_deleted:
#             return user
#         return user

#     def create_admin(self, db: Session, schema: CreateUser) -> User:
#         """Creates a new admin"""

#         if db.query(User).filter(User.email == schema.email).first():
#             raise HTTPException(
#                 status_code=400,
#                 detail="User with this email already exists",
#             )

#         schema.password = self.hash_password(password=schema.password)

#         user = User(**schema.model_dump())

#         user.is_superadmin = True
#         db.add(user)
#         db.commit()
#         db.refresh(user)

#         return user

#     def generate_token(self, email: List[EmailStr]) -> str:
#         """
#         Generates a unique token for email verification.

#         Args:
#             email (EmailStr): A list of recipient email addresses.

#         Returns:
#             str: A unique url-safe, timed token for email verification.

#         Usage:
#             token = generateToken(["john.doe@example.com"])
#         """
#         try:
#             _token = verification_serializer.dumps(email)
#             return _token
#         except Exception as e:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

#     async def send_verification_mail(self, email, http_request, request):
#         try:
#             token = self.generate_token(email)

#             # save generated token with email in a cache
#             # json_cache.set(token, email)

#             verification_url = f"localhost:8000/auth/verify_email/{token}"
#             # token_url =  f"{http_request.url.scheme}://{http_request.client.host}:{http_request.url.port}/auth/verifyemail/{token}"
#             await Email(request.email, verification_url, [email]).send_mail(
#                 "Welcome to Outbound.im", "verification"
#             )

#         except Exception as e:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail=[{"msg": f"{e}"}],
#             )

#         return "Verification email sent successfully"

#     async def send_verification_mail_sendgrid(self, email, http_request, request):
#         """
#         Sends a verification email using SendGrid.

#         Args:
#             email (str): The recipient's email address.
#             http_request (Request): The FastAPI request object.
#             request: The request object containing name.

#         Returns:
#             str: A message indicating the status of the email sending operation.

#         Raises:
#             HTTPException: If there is an error while sending the email.
#         """
#         try:
#             token = self.generate_token(email)

#             # Create verification URL
#             # verification_url = f"http://localhost:8000/auth/verify_email/{token}"
#             # Alternative URL format if needed:
#             verification_url = f"{http_request.url.scheme}://{http_request.client.host}:{http_request.url.port}/auth/verify_email/{token}"

#             # Send verification email using SendGrid
#             await SendGridEmail(
#                 request.email, verification_url, [email]
#             ).send_mail("Welcome to Outbound.im", "verification")

#         except Exception as e:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail=[{"msg": f"SendGrid email error: {e}"}],
#             )

#         return "Verification email sent successfully via SendGrid"

#     def verify_access_token(self, access_token: str, credentials_exception):
#         """Funtcion to decode and verify access token"""
#         # print(f"Type of token: {type(access_token)}, Value: {access_token}")

#         try:
#             payload = jwt.decode(
#                 access_token, settings.SECRET_KEY, algorithms=[
#                     settings.ALGORITHM]
#             )
#             user_id = payload.get("user_id")
#             token_type = payload.get("type")
#             # print(f'line 205: {user_id}')
#             if user_id is None:
#                 raise credentials_exception

#             if token_type == "refresh":
#                 raise HTTPException(
#                     detail="Refresh token not allowed", status_code=400)

#             token_data = TokenData(id=user_id)

#         except JWTError as err:
#             raise credentials_exception

#         return token_data

#     def verify_refresh_token(self, refresh_token: str, credentials_exception):
#         """Funtcion to decode and verify refresh token"""

#         try:
#             payload = jwt.decode(
#                 refresh_token, settings.SECRET_KEY, algorithms=[
#                     settings.ALGORITHM]
#             )
#             user_id = payload.get("user_id")
#             token_type = payload.get("type")

#             if user_id is None:
#                 raise credentials_exception

#             if token_type == "access":
#                 raise HTTPException(
#                     detail="Access token not allowed", status_code=400)

#             token_data = TokenData(id=user_id)

#         except JWTError:
#             raise credentials_exception

#         return token_data

#     def verify_password(self, plain_password: str, hashed_password: str) -> bool:
#         """
#         Verify a plain text password against a hashed password using the bcrypt algorithm.

#         Parameters:
#         plain_password (str): The plain text password to be verified.
#         hashed_password (str): The hashed password to be compared with the plain text password.

#         Returns:
#         bool: True if the plain text password matches the hashed password, False otherwise.

#         Raises:
#         None

#         Note:
#         This function uses the CryptContext class from the passlib library to verify the password.
#         The pwd_context object is assumed to be globally defined and initialized with the bcrypt scheme.
#         """
#         verified: bool = pwd_context.verify(plain_password, hashed_password)
#         return verified
    


#     def check_authorization(self, required_role: str):
#         def get_current_role(
#             token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
#         ):
#             """
#             Retrieve the current user based on the provided access token and check thier role.

#             Parameters:
#             role (str): The role we want to match.
#             token (str, optional): The access token to be used for authentication.
#             If not provided, the function will use the token provided by the OAuth2PasswordBearerWithCookie.
#             db (Session, optional): The database session object to be used for querying the user.
#             If not provided, the function will use the session object provided by the load function.

#             Returns:
#             User: The User object representing the current user.

#             Raises:
#             HTTPException: If the access token is not valid or the user does not exist in the database.

#             Note:
#             This function decodes the access token using the JWT library, retrieves the email from the payload,
#             and queries the database to find the corresponding user.
#             If the access token is not valid or the user does not exist,
#             an HTTPException is raised with appropriate error details.
#             """
#             credentials_exception = HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="401 UNAUTHORIZED",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#             try:
#                 payload = jwt.decode(
#                     token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
#                 )
#                 role = payload.get("role")
#                 email = payload.get("sub")
#                 if role != required_role:
#                     raise credentials_exception
#             except JWTError:
#                 raise credentials_exception
#             user = db.query_eng(User).filter(User.email == email).first()
#             if user is None:
#                 raise credentials_exception
#             return user

#         return get_current_role

    
#     def delete_access_cookies(self, response: Response):
#         """
#         Delete the access token cookie from the response.

#         Parameters:
#         response (Response): The FastAPI response object from which the cookie will be removed.

#         Returns:
#         None

#         Note:
#         This function sets the access token cookie with an empty value and appropriate cookie attributes.
#         The cookie will be deleted from the client's browser when it expires.
#         The domain is set to outboundai's domain to ensure that the cookie is accessible across all subdomains.
#         The secure flag is set to True to ensure that the cookie is only transmitted over HTTPS.
#         The httponly flag is set to True to prevent client-side scripting from accessing the cookie.
#         The samesite attribute is set to "none" to allow cross-site requests to include the cookie.
#         """
#         # response.set_cookie(
#         #     key="access_token",
#         #     value="",
#         #     path="/",
#         #     domain="",
#         #     secure=True,
#         #     httponly=True,
#         #     samesite="none",
#         #     expires=0,  # Set the cookie to expire immediately
#         # )

#         response.delete_cookie("access_token")
#         response.delete_cookie("refresh_token")

#     def verify_refresh_token(self, refresh_token: str, credentials_exception):
#         """Funtcion to decode and verify refresh token"""

#         try:
#             payload = jwt.decode(
#                 refresh_token, settings.SECRET_KEY, algorithms=[
#                     settings.ALGORITHM]
#             )
#             user_id = payload.get("user_id")
#             token_type = payload.get("type")

#             if user_id is None:
#                 raise credentials_exception

#             if token_type == "access":
#                 raise HTTPException(
#                     detail="Access token not allowed", status_code=400)

#             token_data = TokenData(id=user_id)

#         except JWTError:
#             raise credentials_exception

#         return token_data


#     def refresh_access_token(self, current_refresh_token: str):
#         """Function to generate new access token and rotate refresh token"""

#         credentials_exception = HTTPException(
#             status_code=401, detail="Refresh token expired"
#         )

#         token = self.verify_refresh_token(
#             current_refresh_token, credentials_exception)

#         if token:
#             access = self.create_access_token(user_id=token.id)
#             refresh = self.create_refresh_token(user_id=token.id)

#             return access, refresh

#     def change_password(
#         self,
#         new_password: str,
#         user: User,
#         db: Session,
#         old_password: Optional[str] = None
#     ):
#         """Endpoint to change the user's password"""
#         user.password = self.hash_password(new_password)
#         db.commit()

#     def get_current_admin(
#         self, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
#     ):
#         """
#         Get the current admin user based on the provided access token.
        
#         Parameters:
#         db (Session): The database session
#         token (str): The access token
        
#         Returns:
#         User: The admin user
        
#         Raises:
#         HTTPException: If the user is not an admin
#         """
#         user = self.get_current_user(token=token, db=db)
#         if not user.is_admin:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail="You do not have permission to access this resource",
#             )
#         return user

#     def get_current_user_in_organisation(self, organisation_id: str, user: User) -> User:
#         """Retrieve the current user only if they belong to the specified organization."""
#         if not any(organisation_id == org.id for org in user.organisations):
#             if not any(organisation_id == org.id for org in user.owned_organisations):
#                 raise HTTPException(
#                     status_code=status.HTTP_403_FORBIDDEN,
#                     detail="User does not belong to this organization"
#                 )

#         return user

#     def require_org_access(self):
#         def decorator(func):
#             @wraps(func)
#             async def wrapper(request: Request, *args, **kwargs):
#                 db: Session = kwargs.get("db") or next(get_db())

#                 # Extract and validate access token
#                 # authorization: str = request.headers.get("Authorization")
#                 # if not authorization or not authorization.startswith("Bearer "):
#                 #     raise HTTPException(
#                 #         status_code=401, detail="Invalid or missing authorization token")

#                 # access_token = authorization.split("Bearer ")[1]

#                 access_token_plain = request.cookies.get("access_token", "").strip()

#                 if access_token_plain.lower().startswith("bearer "):
#                     access_token = access_token_plain[7:]
#                 else:
#                     access_token = access_token_plain

#                 # # Verify token and get user
#                 token = self.verify_access_token(access_token, HTTPException(
#                     status_code=401,
#                     detail="Could not validate credentials",
#                     headers={"WWW-Authenticate": "Bearer"},
#                 ))

#                 user = check_model_existence(db, User, token.id)
#                 if not user:
#                     raise HTTPException(
#                         status_code=404, detail="User not found")

#                 # Get organization ID from request parameters
#                 org_id = kwargs.get("campaign").organization_id
#                 if not org_id:
#                     body = await request.json()  # Read request body (only if not in kwargs)
#                     org_id = body.get("organization_id")
#                 org_id = check_model_existence(db, Organisation, org_id)

#                 if not org_id:
#                     raise HTTPException(
#                         status_code=400, detail="Organization ID is required")

#                 # Validate user's access to the organization
#                 self.get_current_user_in_organisation(org_id.id, user)

#                 return func(request, *args, **kwargs)

#             return wrapper
#         return decorator


user_service = UserService()
