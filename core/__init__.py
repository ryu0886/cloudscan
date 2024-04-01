from core.sample import analyze as analyze_sample
from core.analysis import parse_log
import os


MAIN_WORK_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_APP_32 = os.path.join(MAIN_WORK_DIR, "minidbg.exe")
MAIN_APP_64 = os.path.join(MAIN_WORK_DIR, "minidbg64.exe")
