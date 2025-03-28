import os
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, HTTPException, Request
from clerk_backend_api.jwks_helpers import AuthenticateRequestOptions
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from clerk_backend_api import Clerk
from starlette.responses import FileResponse 

app = FastAPI()

CLERK_SECRET = os.getenv("CLERK_SECRET")
if not CLERK_SECRET.startswith("Bearer "):
    BEARER_CLERK_SECRET = f"Bearer {CLERK_SECRET}"

clerk = Clerk(bearer_auth=BEARER_CLERK_SECRET)

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str = None
    last_name: str = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    username: str

@app.post("/signup")
async def signup(request: SignupRequest):
    try:
        user = clerk.users.create(
            email_address=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
        )
        return {"message": "User created", "user_id": user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# simulate fontend behavior -- NEEED FRONTEND FOR FAPI
@app.post("/login")
async def login(request: LoginRequest):
    try:
        user_list = clerk.users.list()
        user_id = None
        for user in user_list:
            for email_obj in user.email_addresses:
                if email_obj.email_address.lower() == request.email.lower():
                    user_id = user.id
                    break
            if user_id:
                break

        if not user_id:
            raise HTTPException(status_code=404, detail="User not found in List")

        verified_user = clerk.users.verify_password(
            user_id=user_id,
            password=request.password
        )

        if not verified_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        session = clerk.sessions.create_session(request={"user_id": str(user_id)})
        
        if not session:
            raise HTTPException(status_code=401, detail="Session creation failed")

        token_response = clerk.sessions.create_session_token(
            session_id=session.id,
            # expires_in_seconds=600.00 <--- This is broken in SDK
            )
        
        if not token_response:
            raise HTTPException(status_code=401, detail="Token creation failed")
        

        response = JSONResponse({"access_token": token_response.jwt, "session_id": session.id})
        response.set_cookie(key="__session", value=token_response.jwt, httponly=True, samesite="lax")

        return response

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/protected")
async def protected_route(request: Request):
    ar_options = AuthenticateRequestOptions(
        secret_key=CLERK_SECRET,
    )
    print("Auth Options:", ar_options)
    try:
        state = clerk.authenticate_request(request, ar_options)
        print("State:", state)
    except Exception as e:
        print("Auth Error:", str(e))
        raise HTTPException(status_code=401, detail=str(e))

    if not state.is_signed_in:
        raise HTTPException(status_code=401, detail=state.message)
    return FileResponse("./protected.html")

@app.get("/")
async def root():
    return FileResponse("./index.html")