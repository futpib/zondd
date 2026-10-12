"""Blocking client for a service-side adapter's private stdin/stdout protocol.

Keep stdout for this protocol. Never put answers in logs or exception messages.
Application automation belongs in the adapter, not in this module.
"""
import json
import sys


class Broker:
    def __init__(self, incoming=None, outgoing=None):
        self.incoming = incoming or sys.stdin
        self.outgoing = outgoing or sys.stdout
        ready = self.receive()
        if ready.get('type') != 'ready' or ready.get('version') != 1:
            raise RuntimeError('Unsupported zond adapter protocol')
        self.session_id = ready['session_id']

    def send(self, method, **body):
        self.outgoing.write(json.dumps(dict(method=method, **body)) + '\n')
        self.outgoing.flush()

    def receive(self):
        line = self.incoming.readline(1024 * 1024 + 1)
        if not line.endswith('\n') or len(line) > 1024 * 1024:
            raise RuntimeError('Zond adapter channel closed or frame too large')
        try:
            message = json.loads(line)
        except ValueError:
            raise RuntimeError('Invalid zond response') from None
        if message.get('type') == 'error':
            raise RuntimeError('Zond rejected the adapter request')
        return message

    def challenge(self, prompt, fields, *, context=None, timeout_secs=86400):
        self.send('challenge', prompt=prompt, fields=fields,
                  context=context, timeout_secs=timeout_secs)
        opened = self.receive()
        if opened.get('type') != 'opened':
            raise RuntimeError('Expected a new challenge')
        return opened['challenge_id']

    def answer(self, challenge_id):
        answer = self.receive()
        if answer.get('type') != 'answered' or answer.get('challenge_id') != challenge_id:
            raise RuntimeError('Expected an answer for this challenge')
        return answer.get('values')

    def withdraw(self, challenge_id):
        self.send('withdraw', challenge_id=challenge_id)
        self._recorded()
        return self.answer(challenge_id)

    def result(self, challenge_id, outcome):
        self.send('result', challenge_id=challenge_id, outcome=outcome)
        self._recorded()

    def status(self, state):
        self.send('status', state=state)
        self._recorded()

    def _recorded(self):
        if self.receive().get('type') != 'recorded':
            raise RuntimeError('Expected broker acknowledgement')
