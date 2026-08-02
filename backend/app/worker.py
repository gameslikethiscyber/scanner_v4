import os
import sys

ENGINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

from celery import Celery

celery_app = Celery(
    "sea_scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    imports=["app.scan_runner"],
)

celery_app.autodiscover_tasks(["app"])
