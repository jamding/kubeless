#!/usr/bin/env python

import os
import imp
import datetime

from multiprocessing import Process, Queue
import bottle
import prometheus_client as prom
from cheroot import wsgi
from cheroot.ssl.builtin import BuiltinSSLAdapter
import ssl

mod = imp.load_source('function',
                      '/kubeless/%s.py' % os.getenv('MOD_NAME'))
func = getattr(mod, os.getenv('FUNC_HANDLER'))
func_port = os.getenv('FUNC_PORT', 8080)
func_port_https = os.getenv('FUNC_PORT_HTTPS', 8090)
certfile = os.getenv('CERT_FILE_PATH')
keyfile = os.getenv('KEY_FILE_PATH')


tls_enabled = certfile and keyfile
# See https://github.com/bottlepy/bottle/issues/934
class TlsServerAdapter(bottle.ServerAdapter):
    def run(self, handler):
        server = wsgi.Server((self.host, self.port), handler)
        server.ssl_adapter = BuiltinSSLAdapter(certfile, keyfile)
        server.ssl_adapter.context.options |= ssl.OP_NO_TLSv1
        server.ssl_adapter.context.options |= ssl.OP_NO_TLSv1_1
        try:
            server.start()
        finally:
            server.stop()


timeout = float(os.getenv('FUNC_TIMEOUT', 180))

app = application = bottle.app()

func_hist = prom.Histogram('function_duration_seconds',
                           'Duration of user function in seconds',
                           ['method'])
func_calls = prom.Counter('function_calls_total',
                           'Number of calls to user function',
                          ['method'])
func_errors = prom.Counter('function_failures_total',
                           'Number of exceptions in user function',
                           ['method'])

function_context = {
    'function-name': func,
    'timeout': timeout,
    'runtime': os.getenv('FUNC_RUNTIME'),
    'memory-limit': os.getenv('FUNC_MEMORY_LIMIT'),
}

def funcWrap(q, event, c):
    try:
        q.put(func(event, c))
    except Exception as inst:
        q.put(inst)

@app.route('/', method=['GET', 'POST', 'PATCH', 'DELETE'])
def handler():
    req = bottle.request
    content_type = req.get_header('content-type')
    data = req.body.read()
    if content_type == 'application/json':
        data = req.json
    event = {
        'data': data,
        'event-id': req.get_header('event-id'),
        'event-type': req.get_header('event-type'),
        'event-time': req.get_header('event-time'),
        'event-namespace': req.get_header('event-namespace'),
        'extensions': {
            'request': req
        }
    }
    method = req.method
    func_calls.labels(method).inc()
    with func_errors.labels(method).count_exceptions():
        with func_hist.labels(method).time():
            q = Queue()
            p = Process(target=funcWrap, args=(q, event, function_context))
            p.start()
            p.join(timeout)
            # If thread is still active
            if p.is_alive():
                p.terminate()
                p.join()
                return bottle.HTTPError(408, "Timeout while processing the function")
            else:
                res = q.get()
                if isinstance(res, Exception):
                    raise res
                return res

@app.get('/healthz')
def healthz():
    return 'OK'

@app.get('/metrics')
def metrics():
    bottle.response.content_type = prom.CONTENT_TYPE_LATEST
    return prom.generate_latest(prom.REGISTRY)


def monitor_child(child_pid):
    _pid, status = os.waitpid(child_pid)
    os.exit(status)


if __name__ == '__main__':
    import logging
    import sys
    import requestlogger
    loggedapp = requestlogger.WSGILogger(
        app,
        [logging.StreamHandler(stream=sys.stdout)],
        requestlogger.ApacheFormatter())

    # when TLS is enabled, create a separate process to listen on the https port
    pid = os.fork()
    if pid == 0:
        if not tls_enabled:
            logging.info("TLS is not enabled, only listening on HTTPS")
            sys.exit(0)
        bottle.run(loggedapp, server=TlsServerAdapter, host='0.0.0.0', port=func_port_https)
    else:
        if tls_enabled:
            from threading import Thread
            watch_child = Thread(target=monitor_child, args=(pid,))
            watch_child.start()
        bottle.run(loggedapp, server='cherrypy', host='0.0.0.0', port=func_port)
