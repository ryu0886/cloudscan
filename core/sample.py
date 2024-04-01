import subprocess
import re
import hashlib
import json
import os
import shutil
import shlex
import pathlib
import time
import signal


def _run_cmd_with_timeout(path, timeout, logger):
    exe_path = pathlib.PureWindowsPath(path).as_posix()
    logger.debug(f"launch {exe_path} >>")
    proc = subprocess.Popen(shlex.split(exe_path), stdout=None, stderr=None)
    try:
        start = time.time()
        end = start + timeout
        result = None
        while time.time() < end:
            time.sleep(1)
            result = proc.poll()
            logger.debug(f"{result}")
            if result is not None:
                logger.debug(f"result {proc.__dict__}")
                return
            else:
                logger.debug("wait..")
            time.sleep(1)
        if result is None:
            logger.debug(f"terminate {proc.__dict__}")
            proc.terminate()
            time.sleep(1)
            logger.debug(f"kill {proc.__dict__}")
            proc.kill()

    except Exception as ex:
        logger.exception(f"error {ex}")
    logger.debug(f"launch {exe_path} <<")


def analyze(loader, sample_sha256, logger):
    logger.debug("analyze>>")
    from core import MAIN_APP_32 as the_main_app
    from core import MAIN_APP_64 as the_main_app64
    from core import parse_log
    sample_dir = os.path.dirname(loader)
    main_name = os.path.basename(loader).split(".")[0]
    ep_bat = f"{main_name}.bat"
    ep_name = f"{main_name}.exe"
    ep64_name = f"{main_name}64.exe"
    ep_path = os.path.join(sample_dir, ep_name)
    ep64_path = os.path.join(sample_dir, ep64_name)
    dest_path = shutil.copyfile(the_main_app, ep_path)
    dest_path64 = shutil.copyfile(the_main_app64, ep64_path)
    logger.debug(dest_path)
    logger.debug(dest_path64)
    try:
        _run_cmd_with_timeout(dest_path, 60, logger)  # noqa
    except Exception as ex:
        logger.exception(f"kill fail {ex}")
    log_name = f"{main_name}.log"
    log_path = os.path.join(sample_dir, log_name)
    logger.debug(log_path)
    log_path2 = pathlib.PureWindowsPath(log_path).as_posix()
    logger.debug(log_path2)
    json_res = parse_log(log_path2, ep_bat, sample_sha256)
    logger.debug("analyze_sample<<")
    return json_res
