import subprocess

from .. import config


def run(number):
    subprocess.run(config.EXPORT_COMMAND + " --number " + number, shell=True, check=True)  # fsb-allow: FSB-CMD-003
