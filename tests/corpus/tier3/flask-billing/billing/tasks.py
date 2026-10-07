from celery import Celery

from .services import export

app = Celery("billing", broker="redis://localhost:6379/0")


@app.task
def export_invoice(number):
    export.run(number)  # fsb-expect: FSB-CMD-001
