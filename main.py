from flask import Flask
from flask import render_template
from flask import abort, jsonify, url_for
from flask import request, redirect
from werkzeug.utils import secure_filename
import os
import logging
import uuid
import json
import hashlib
import shutil


logging.basicConfig(filename="cloudscan.log", level=logging.DEBUG)
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "C:/inetpub/cloudscan/upload"


class Global:
    def __init__(self):
        self.cache = {}


g_ctx = Global()


@app.route("/hello")
def hello():
    app.logger.debug('Hello')
    print("test")
    return "Hello!"


@app.route("/", methods=['GET', 'POST'])
def main():
    """
    curl -v -k -XPOST -H "apikey:INTERNAL_TEST" -F file="@$1" https://127.0.0.1/
    """  # noqa: E501
    return redirect(url_for('sample'))


@app.route("/sample", methods=['GET', 'POST'])
def sample():
    """
    curl -v -k -XPOST -H "apikey:INTERNAL_TEST" -F file="@$1" https://127.0.0.1/sample
    """  # noqa: E501
    global g_ctx
    default_cmd = ""
    if request.method == 'POST':
        app.logger.debug("request.headers:%s", request.headers)
        app.logger.debug("request.files:%s", request.files)
        app.logger.debug("request.form:%s", request.form)
        if 'file' not in request.files:
            app.logger.debug('No file part')
            return ""
        file = request.files['file']
        if file.filename == '':
            app.logger.debug('No selected file')
            return ""
        app.logger.debug("receive file name:%s", file.filename)
        default_cmd = file.filename
        # filename = secure_filename(file.filename)
        _sample_name = "{basename}.{extension}".format(basename=hashlib.md5(file.filename.encode()).hexdigest(), extension=file.filename.split(".")[-1])  # noqa: E501
        _uuid_ = str(uuid.uuid1())
        sample_dir = os.path.join(app.config['UPLOAD_FOLDER'], _uuid_)
        os.makedirs(sample_dir)
        _sample_path = os.path.join(sample_dir, _sample_name)
        file.save(_sample_path)
        with open(_sample_path, 'rb') as f:
            _sample_sha256 = hashlib.sha256(f.read()).hexdigest()
        if _sample_sha256 not in g_ctx.cache:
            app.logger.debug(f"{_sample_sha256} not in cache")
            _loader_path = os.path.join(sample_dir, "loader.bat")
            with open(_loader_path, 'w') as f:
                f.write(f"{_sample_path}")
            import core
            app.logger.debug("check:%s", _loader_path)
            res = core.analyze_sample(_loader_path, _sample_sha256, app.logger)
            g_ctx.cache[_sample_sha256] = res
        else:
            app.logger.debug(f"{_sample_sha256} in cache")
            res = g_ctx.cache[_sample_sha256]

        try:
            shutil.rmtree(sample_dir)
        except Exception as ex:
            pass
        return "{}".format(res)

    return '''
    <!doctype html>
    <title>Cloud Sample Scanner</title>
    <h1>Windows Cloud Sample Scanner</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file><br>
      launcher command:<input type=text size="32" placeholder="how to launch your sample" value="{value}" name=launcher><br>
      <input type=submit value=Upload><br>
    </form>
    '''.format(value=default_cmd)  # noqa: E501


if __name__ == "__main__":
    app.run()
