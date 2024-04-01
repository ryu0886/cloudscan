import sys
import json
import os
import argparse
import logging
import uuid
import hashlib
import shutil


logger = logging.getLogger(__name__)


def test_analyze_sample(filepath, workdir):
    _uuid_ = str(uuid.uuid1())
    _sample_name = "{basename}.{extension}".format(basename=hashlib.md5(os.path.basename(filepath).encode()).hexdigest(), extension=os.path.basename(filepath).split(".")[-1])  # noqa: E501
    sample_dir = os.path.join(workdir, _uuid_)
    os.makedirs(sample_dir)
    _sample_path = os.path.join(sample_dir, _sample_name)
    dest_path = shutil.copyfile(filepath, _sample_path)
    _loader_path = os.path.join(sample_dir, "loader.bat")
    with open(_loader_path, 'w') as f:
        f.write(f"{_sample_path}")
    import core
    logger.debug("check:%s", _loader_path)
    res = core.analyze_sample(_loader_path, logger)
    try:
        shutil.rmtree(sample_dir)
    except Exception as ex:
        pass


def test_parse_log(logfile, loader, sample_sha256):
    import core
    res = core.parse_log(logfile, loader, sample_sha256)
    logger.info(json.dumps(res))


if __name__ == "__main__":
    import logging
    import logging.handlers

    parser = argparse.ArgumentParser(description='')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument('-t', '--type', dest='type', default="analyze")
    parser.add_argument('-f', '--file', dest='file', default="sample")
    parser.add_argument('-s', '--sha256', dest='sha256', default="sha256")
    parser.add_argument('-l', '--loader', dest='loader', default="loader.bat")
    parser.add_argument('-d', '--workdir', dest='workdir', default="upload")

    args = parser.parse_args()

    logger = logging.getLogger()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s %(name)s %(threadName)s %(levelname)s "
        "%(module)s.%(funcName)s:%(lineno)d %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if args.type == "analyze":
        test_analyze_sample(args.file, args.workdir)
    elif args.type == "parse_log":
        test_parse_log(args.file, args.loader, args.sha256)
