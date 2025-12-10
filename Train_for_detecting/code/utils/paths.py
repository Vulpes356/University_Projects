import os
import sys
from pathlib import Path

def get_base_dir():
    try:
        current_path = Path(__file__).resolve()
        return current_path.parents[2]
    except NameError:
        return Path(os.getcwd()).resolve()

def setup_sys_path():
    base_dir = get_base_dir()
    if str(base_dir) not in sys.path:
        sys.path.append(str(base_dir))
    code_dir = base_dir / "code"
    if str(code_dir) not in sys.path:
        sys.path.append(str(code_dir))