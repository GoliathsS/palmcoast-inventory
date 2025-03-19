import subprocess
import threading
import time
import webbrowser
import os
import sys

# Optional: Set your ngrok.exe path here if it's not in PATH
NGROK_PATH = "D:/ngrok/ngrok.exe"  # 🔁 update this for each PC

def run_flask():
    # Run app.py from the same folder as this script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(current_dir, "app.py")
    if not os.path.exists(app_path):
        print(f"[ERROR] Could not find app.py at {app_path}")
        sys.exit(1)
    os.system(f"python {app_path}")

def run_ngrok():
    time.sleep(2)  # Let Flask start first
    print("[INFO] Launching ngrok...")
    subprocess.Popen([NGROK_PATH, "http", "5000"])
    time.sleep(3)
    print("[INFO] ngrok tunnel active! Copy the HTTPS link below:\n")
    os.system("curl http://127.0.0.1:4040/api/tunnels")

if __name__ == "__main__":
    threading.Thread(target=run_flask).start()
    run_ngrok()
