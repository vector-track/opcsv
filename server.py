import os
import csv
import uuid

from collections import OrderedDict
from flask import Flask, request, render_template, redirect, g

CSV_DIR = os.path.join(os.getcwd(), 'inputs/')
OP_DIR = os.path.join(os.getcwd(), 'outputs/')

UNIQUE_SUFFIX = '.opcsv'
KEY = 'opcsv-enum'

class Annotation(object):
    def __init__(self, name, format, html=False):
        self.name = name
        self.format = format
        self.html = html

class OPCSVKey(object):
    NEW = 0
    TRIAGED = 1
    FLAGGED = 2
    OK = 3

    def __init__(self, name=KEY):
        self.name = name

    def default(self):
        return self.NEW

    def annotations_from_raw(self, row, csv_row):
        value = int(row[self.name])
        status_annotation = Annotation('Status', '')
        if value == OPCSVKey.NEW:
            status_annotation.format = 'NEW'
        elif value == OPCSVKey.TRIAGED:
            status_annotation.format = 'NEW'
        elif value == OPCSVKey.FLAGGED:
            status_annotation.format = 'NEW'
        elif value == OPCSVKey.OK:
            status_annotation.format = 'OK'
        shodan_annotation = Annotation('Shodan', "<a target='_blank' href='https://shodan.io/host/{}'>Click</a>".format(csv_row['IP']), True)
        return [status_annotation, shodan_annotation]

class CSVQueryResponse(object):
    def __init__(self):
        self.csv = None
        self.op = None
        self.error = None
        self.closed = False


class CSVQueryService(object):
    def __init__(self, output_dir=OP_DIR, target_dir=CSV_DIR, suffix=UNIQUE_SUFFIX, key=OPCSVKey()):
        self.target_dir = target_dir
        self.output_dir = output_dir
        self.suffix = suffix
        self.key = key

    def has_op(self, fullpath):
        op_path = fullpath.replace(self.target_dir, self.output_dir)
        return os.path.isfile(op_path + self.suffix)

    def is_op(self, fullpath):
        return fullpath.endswith(UNIQUE_SUFFIX)

    def get_inputs(self):
        files = []
        for f in os.listdir(self.target_dir):
            fullpath = os.path.join(self.target_dir, f)
            if os.path.isfile(fullpath):
                files.append(fullpath.split('/')[-1])
        return files

    def _make_opcsv(self, name):
        response = CSVQueryResponse()
        fullpath = os.path.join(self.target_dir, name)
        if not os.path.isfile(fullpath):
            response.error = "CSV not found."
        elif self.has_op(fullpath):
            response.error = "OPCSV already exists."
        else:
            write_path = fullpath.replace(self.target_dir, self.output_dir) + self.suffix
            with open(fullpath) as f:
                with open(write_path, 'w') as g:
                    reader = csv.DictReader(f)
                    writer = csv.DictWriter(g, fieldnames=[self.key.name, ])
                    writer.writeheader()
                    for line in reader:
                        writer.writerow({self.key.name: self.key.default()})

            response.csv = open(fullpath)
            response.opcsv = open(write_path)
        return response

    def _get_opcsv(self, name):
        response = CSVQueryResponse()
        fullpath = os.path.join(self.target_dir, name)
        if not os.path.isfile(fullpath):
            response.error = "CSV not found"
        elif not self.has_op(fullpath):
            response.error = "OPPCSV not found"
        else:
            response.csv = open(fullpath)
            response.opcsv = open(fullpath.replace(self.target_dir, self.output_dir) + self.suffix)
        return response

    def get_opcsv(self, name):
        response = CSVQueryResponse()
        fullpath = os.path.join(self.target_dir, name)
        if not os.path.isfile(fullpath):
            c.error = "CSV not found."
        elif not self.has_op(fullpath):
            return self._make_opcsv(name)
        else:
            return self._get_opcsv(name)

class CSVIterService(object):
    def __init__(self, _csv, opcsv):
        self.csv = csv.DictReader(_csv)
        self.opcsv = csv.DictReader(opcsv)

        self.opcsv_draft = csv.DictWriter(open(opcsv.name + '.draft', 'w'), fieldnames=self.opcsv.fieldnames)
        self.opcsv_draft.writeheader()
        self.counter = 0

        self.get_next()

    @staticmethod
    def from_csv_response(csv_response):
        csv_response.closed = True
        return CSVIterService(csv_response.csv, csv_response.opcsv)

    def get_next(self):
        self.current_csv_row = next(self.csv)
        self.current_annotations = current_key.annotations_from_raw(next(self.opcsv), self.current_csv_row)
        self.counter += 1



QUERY_SERVICE = CSVQueryService()
state = {'iter': None, 'name': None}

current_key = OPCSVKey()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SESSION_KEY", "someappsecretkey")

@app.route('/')
def index():
    return render_template('index.html', files=QUERY_SERVICE.get_inputs())

@app.route('/csv/<csv_name>')
def open_csv(csv_name):
    state['name'] = csv_name
    if state['iter'] is None:
        query_response = QUERY_SERVICE.get_opcsv(csv_name)
        state['iter'] = CSVIterService.from_csv_response(query_response)
    return render_template('opcsv.html', csv_row=state['iter'].current_csv_row, annotations=state['iter'].current_annotations, name=state['name'])

@app.route('/csv/next')
def get_next():
    if state['iter'] is None:
        return redirect('/')
    state['iter'].get_next()
    return redirect('/csv/' + state['name'])

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=True)
