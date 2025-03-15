from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1.routes import api_version_one
import uvicorn

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_version_one)

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/probe", tags=["Home"])
async def probe():
    return {"message": "I am the Python FastAPI API responding"}


# # REGISTER EXCEPTION HANDLERS
# @app.exception_handler(HTTPException)
# async def http_exception(request: Request, exc: HTTPException):
#     """HTTP exception handler"""

#     return JSONResponse(
#         status_code=exc.status_code,
#         content={
#             "status": False,
#             "status_code": exc.status_code,
#             "message": exc.detail,
#         },
#     )




# @app.exception_handler(RequestValidationError)
# async def validation_exception(request: Request, exc: RequestValidationError):
#     """Validation exception handler"""

#     errors = [
#         {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
#         for error in exc.errors()
#     ]

#     return JSONResponse(
#         status_code=422,
#         content={
#             "status": False,
#             "status_code": 422,
#             "message": "Invalid input",
#             "errors": errors,
#         },
#     )


if __name__ == "__main__":
    uvicorn.run("main:app",port = 8000, reload=True)
