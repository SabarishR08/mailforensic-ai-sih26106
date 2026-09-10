"""Flask extensions with graceful fallback if flask_socketio is not installed"""

try:
    from flask_socketio import SocketIO
    socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')
except ImportError:
    class DummySocketIO:
        def init_app(self, app):
            pass
        def emit(self, *args, **kwargs):
            pass
        def on(self, *args, **kwargs):
            return lambda f: f
        def run(self, app, **kwargs):
            host = kwargs.get('host', '127.0.0.1')
            port = kwargs.get('port', 5000)
            debug = kwargs.get('debug', False)
            app.run(host=host, port=port, debug=debug)
    socketio = DummySocketIO()
