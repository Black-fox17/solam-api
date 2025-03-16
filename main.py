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



if __name__ == "__main__":
    uvicorn.run("main:app",port = 8000, reload=True)
