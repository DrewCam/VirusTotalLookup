import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise RuntimeError("VirusTotal API key is missing. Set VT_API_KEY in your environment or .env file")

API_URL_BASE = "https://www.virustotal.com/api/v3/"

RATE_LIMIT_DELAY = 15  # 4 requests per minute
DAILY_LIMIT = 500  # VirusTotal public API daily limit

ROOT_DIR = Path(__file__).resolve().parent.parent
input_file_path = ROOT_DIR / "raw.txt"
output_file_path = ROOT_DIR / "out.txt"
report_file_path = ROOT_DIR / "virustotal_report.txt"
