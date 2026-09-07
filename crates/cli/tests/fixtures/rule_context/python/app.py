import subprocess
import shlex
import urllib.parse
import os
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect-encoded')
def redirect_encoded():
    return redirect(urllib.parse.quote(request.args.get('next')))

@app.route('/redirect-control')
def redirect_control():
    return redirect(request.args.get('next'))

@app.route('/run-noshell')
def run_noshell():
    return subprocess.run(request.args.get('exe'), shell=False)

@app.route('/run-shell-control')
def run_shell_control():
    return subprocess.run(request.args.get('exe'), shell=True)

@app.route('/shlex-exec')
def shlex_exec():
    return os.execv(shlex.quote(request.args.get('exe')), ['program'])

@app.route('/xml')
def xml_input():
    return ET.fromstring(request.args.get('xml'))
