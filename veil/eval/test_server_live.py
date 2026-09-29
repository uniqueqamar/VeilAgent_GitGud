import subprocess
import sys
import time
import urllib.request
from pathlib import Path

server_dir = Path(__file__).resolve().parent.parent / "server"

def test_live_server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(server_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    try:
        # Wait up to 5 seconds for server to start
        connected = False
        for _ in range(10):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=1) as resp:
                    if resp.status == 200:
                        data = resp.read().decode("utf-8")
                        print("Health check response:", data)
                        connected = True
                        break
            except Exception:
                pass

        assert connected, "Could not connect to live server on http://127.0.0.1:8000"
        print("[PASS] Live server booted and responded successfully to /health")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        print("Server stopped cleanly.")

if __name__ == "__main__":
    test_live_server()
