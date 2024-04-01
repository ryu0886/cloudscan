import base64
import json
import logging


logger = logging.getLogger(__name__)


class CSample:
    def __init__(self, pid, image, sha256):
        self.pid = pid
        self.image = image
        self.basename = self.image.split("\\")[-1]
        self.sha256 = sha256
        self.api_count = {}
        self.behavior = []

    def __repr__(self):
        _ = dict(sorted(self.api_count.items(), key=lambda item: item[1], reverse=True))  # noqa: E501
        return f"'(pid={self.pid}, image={self.image}, sha256={self.sha256}, behavior={self.behavior}, {_}'"  # noqa: E501

    def __str__(self):
        _ = dict(sorted(self.api_count.items(), key=lambda item: item[1], reverse=True))  # noqa: E501
        return f"pid={self.pid}, image={self.image}, sha256={self.sha256}, behavior={self.behavior}, {_}"  # noqa: E501

    def add_behavior(self, res):
        self.behavior.append(res)
        self.behavior = list(set(self.behavior))


class AnalysisContext:
    def __init__(self, loader_pid, sample_sha256, sample_pid, sample_image, sample_cmd, sha256_in_log):  # noqa: E501
        self.start = False
        self.loader_pid = loader_pid
        self.sample_sha256 = sample_sha256
        self.sample_pid = sample_pid
        self.sample_image = sample_image
        self.sample_cmd = sample_cmd
        self.sha256_in_log = sha256_in_log
        self.all_records = {}
        if self.sample_pid not in self.all_records:
            self.all_records[self.sample_pid] = CSample(self.sample_pid, self.sample_image, self.sample_sha256)  # noqa: E501

    def __repr__(self):
        return f"AnalysisContext(loader_pid={self.loader_pid}, sample_sha256={self.sample_sha256}, sample_pid={self.sample_pid}, sample_image={self.sample_image}, sample_cmd={self.sample_cmd}, sha256_in_log={self.sha256_in_log}, all_records={self.all_records})"  # noqa: E501

    def __str__(self):
        return f"loader_pid={self.loader_pid}, sample_sha256={self.sample_sha256}, sample_pid={self.sample_pid}, sample_image={self.sample_image}, sample_cmd={self.sample_cmd}, sha256_in_log={self.sha256_in_log}, all_records={self.all_records}"  # noqa: E501

    def toJSON(self):
        output = {}
        output["loader_pid"] = self.loader_pid
        output["sample_pid"] = self.sample_pid
        output["sample_image"] = self.sample_image
        output["sample_sha256"] = self.sample_sha256
        output["all_records"] = {}
        for pid in self.all_records:
            output["all_records"][pid] = self.all_records[pid].__dict__
        return json.dumps(output)

    def parse_line(self, cols):
        if(len(cols) > 4):
            _ts = int(cols[0], 16)
            _pid = int(cols[1])
            if cols[2] != "enum":
                if _pid == self.loader_pid:
                    pass
                else:
                    _tid = int(cols[2])
                    _type = cols[3]
                    if _type == "process":
                        _image = parse_p(cols[5])
                        _cmd = parse_p(cols[6])
                        _sha256 = parse_p(cols[9])
                        if _pid not in self.all_records:
                            self.all_records[_pid] = CSample(_pid, _image, _sha256)  # noqa: E501
                        logger.debug(f"{_image},{_cmd},{_sha256}")
                    elif _type == "module":
                        _image = parse_p(cols[4])
                        _base = parse_p(cols[5])
                        _sha256 = parse_p(cols[6])
                        logger.debug(f"{_image},{_base},{_sha256}")
                    elif _type == "api":
                        _api_name = parse_p(cols[4])
                        try:
                            if self.all_records[_pid].api_count.get(_api_name) is not None:  # noqa: E501
                                self.all_records[_pid].api_count[_api_name] += 1  # noqa: E501
                            else:
                                self.all_records[_pid].api_count[_api_name] = 1  # noqa: E501
                        except Exception as ex:
                            logger.exception(f"{ex} at {cols}")
                        # simple demo for rules
                        if _api_name == "user32.dll!MessageBoxTimeoutW":
                            lpText = parse_p(cols[6])
                            lpCaption = parse_p(cols[7])
                            res = f"{self.all_records[_pid].basename}(pid={_pid}) pops up a message with lpText={lpText}, lpCaption={lpCaption}"  # noqa: E501
                            logger.debug(res)
                            self.all_records[_pid].add_behavior(res)
                        elif _api_name == "ntdll.dll!NtProtectVirtualMemory":
                            target_pid = int(parse_p(cols[5]))
                            if _pid != target_pid:
                                res = f"{self.all_records[_pid].basename}(pid={_pid}) modifies remote process {self.all_records[target_pid].image}(pid={target_pid})"  # noqa: E501
                                logger.debug(res)
                                self.all_records[_pid].add_behavior(res)
                        elif _api_name == "ntdll.dll!NtCreateThreadEx":
                            target_pid = int(parse_p(cols[8]))
                            if _pid != target_pid:
                                res = f"{self.all_records[_pid].basename}(pid={_pid}) creates a remote thread onto {self.all_records[target_pid].image}(pid={target_pid})"  # noqa: E501
                                logger.debug(res)
                                self.all_records[_pid].add_behavior(res)


def parse_p(_input):
    if _input.startswith("sha256:"):
        return _input[len("sha256:"):]
    elif _input.startswith("pid:"):
        return _input[len("pid:"):]
    elif _input.startswith("b64::"):
        _input[len("b64::"):]
        return base64.b64decode(_input[len("b64::"):]).decode()
    return _input


def parse_log(logfile, loader, sample_sha256):
    logger.debug("parse_log>>>")
    _start = False
    _loader_pid = None
    _sample_pid = None
    _context = None
    import core
    try:
        with open(logfile, 'r') as f:
            for line in f:
                cols = line.split(",")
                if _start:
                    _context.parse_line(cols)
                else:
                    if len(cols) > 4:
                        if cols[3] == "process":
                            _cmd = parse_p(cols[6])
                            if _cmd.find(loader) != -1:
                                _loader_pid = int(cols[1])
                                _loader_image = parse_p(cols[5])
                                _loader_cmd = parse_p(cols[6])
                                _loader_sha256_in_log = parse_p(cols[9])
                                logger.debug(f"loader_pid:{_loader_pid},image:{_loader_image},cmd:{_loader_cmd},sha256:{_loader_sha256_in_log}")  # noqa: E501
                            else:
                                _sample_pid = int(cols[1])
                                _image = parse_p(cols[5])
                                _cmd = parse_p(cols[6])
                                _sha256_in_log = parse_p(cols[9])
                                logger.debug(f"pid:{_sample_pid},image:{_image},cmd:{_cmd},sha256:{_sha256_in_log}")  # noqa: E501
                                _start = True
                                _context = AnalysisContext(_loader_pid, sample_sha256, _sample_pid, _image, _cmd, _sha256_in_log)  # noqa: E501

    except Exception as ex:
        logger.exception(f"error {ex}")
    logger.debug("parse_log<<<")
    return _context.toJSON()
