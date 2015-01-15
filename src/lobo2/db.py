from redis import Redis
from app import app

def connection():
   return Redis(host=app.config.get("REDIS_HOST", 'localhost'), port=int(app.config.get("REDIS_PORT", "6379")))
