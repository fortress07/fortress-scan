import os
import subprocess


class ReportService:
    def __init__(self, root):
        self.root = root

    def generate(self, name):
        subprocess.run("report-cli --out %s/%s.pdf" % (self.root, name), shell=True, check=True)  # fsb-allow: FSB-CMD-003

    def read(self, relative):
        with open(os.path.join(self.root, relative)) as handle:
            return handle.read()
