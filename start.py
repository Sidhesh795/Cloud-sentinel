import os
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting CloudSentinel backend on {host}:{port}...")
    uvicorn.run("backend.main:app", host=host, port=port, log_level="info")
