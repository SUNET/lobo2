from redis import Redis

_rc = None

def connection():
   from . import app
   if _rc is None:
      _rc = Redis(host=app.config.get("REDIS_HOST", 'localhost'), port=int(app.config.get("REDIS_PORT", "6379")))
   return _rc
