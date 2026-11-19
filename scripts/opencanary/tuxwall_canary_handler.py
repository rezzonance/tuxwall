"""Webhook handler for the tuxwall OpenCanary deployment.

opencanary.logger.SlackHandler posts with requests.post() and NO timeout,
from inside the twisted reactor: a hung dashboard API would freeze every
emulator. This subclass sends the same Slack-style payload with a short
timeout and never raises, so a slow or restarting API costs at most a few
seconds and one lost webhook (the event is still in opencanary.log).

Installed into the canary venv by scripts/opencanary/deploy-opencanary.sh
and referenced from opencanary.conf.tmpl
("()": "tuxwall_canary_handler.TimeoutSlackHandler").
"""
import sys

import requests
from opencanary.logger import SlackHandler

WEBHOOK_TIMEOUT = (2, 5)    # connect, read (seconds)


class TimeoutSlackHandler(SlackHandler):
    def emit(self, record):
        try:
            data = self.generate_msg(record)
            response = requests.post(self.webhook_url, json=data, timeout=WEBHOOK_TIMEOUT)
            if response.status_code != 200:
                print("tuxwall webhook: HTTP %s" % response.status_code, file=sys.stderr)
        except Exception as exc:  # never let a webhook failure reach the reactor
            print("tuxwall webhook failed: %s" % type(exc).__name__, file=sys.stderr)
