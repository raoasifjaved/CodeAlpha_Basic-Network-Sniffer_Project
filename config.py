import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
@dataclass(frozen=True)
class Settings:
    max_packets: int
    max_payload_preview: int
    database_path: str
settings = Settings(
    max_packets=int(os.getenv("MAX_PACKETS", "200")),
    max_payload_preview=int(os.getenv("MAX_PAYLOAD_PREVIEW", "64")),
    database_path=os.getenv("DATABASE_PATH", str(BASE_DIR / "netscope.db")),
)
