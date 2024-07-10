from typing import List

import pymongo
import requests as r
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from os import getenv
from dotenv import load_dotenv

from helper import PostModel, generate_public_code, is_valid_code, generate_private_code, get_meower_token

app = FastAPI()


@app.post("/generate-token")
async def generate_token(username: str):
    if not username:
        raise HTTPException(status_code=400, detail="Username not included")
    if len(username) < 1 or len(username) > 20:
        raise HTTPException(status_code=400, detail="Invalid username")
    payload = {
        "username": username,
        "publicCode": await generate_public_code(),
        "privateCode": await generate_private_code(32)
    }
    db.tokens.insert_one(payload)
    del payload["_id"]
    return payload

@app.post("/verify-token")
async def verify_token(privateCode: str):
    supposed_token = db.tokens.find_one({"privateCode": privateCode})
    if not supposed_token:
        raise HTTPException(status_code=401, detail="Invalid auth code")
    
    username = supposed_token["username"]
    public_code = supposed_token["publicCode"]
    
    user = r.get(f"https://api.meower.org/users/{username}")

    if user.status_code == 404:
        raise HTTPException(status_code=404, detail="User not found")
    
    meower_token = await get_meower_token(getenv("MEOWER_USERNAME"), getenv("MEOWER_PASSWORD"))

    dm_id: str = r.get(f"https://api.meower.org/users/{username}/dm", headers={"Token": meower_token}).json()["_id"]
    dm_posts: List[PostModel] = [
        PostModel(**post)
        for post in r.get(f"https://api.meower.org/posts/{dm_id}", headers={"Token": meower_token}).json()["autoget"]
    ]
    if len(dm_posts) < 1:
        raise HTTPException(status_code=401, detail="Auth code not sent")
    supposed_code = dm_posts[0].p  # most recent post (they get sorted in server)

    if not await is_valid_code(supposed_code):
        raise HTTPException(status_code=401, detail="Invalid auth code")
    
    if not supposed_code == public_code:
        raise HTTPException(status_code=401, detail="Wrong auth code")
    
    return {"valid": True, "username": username}

if __name__ == "__main__":
    load_dotenv()
    print("Connecting to MongoDB...")
    try:
        db = pymongo.MongoClient(getenv("MONGODB_URI"))["meowerauth"]
        db.command("ping")
    except Exception as e:
        exit(f"Failed to connect to MongoDB! Error: {e}")
    print("Connected to MongoDB!")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )


    uvicorn.run(app)