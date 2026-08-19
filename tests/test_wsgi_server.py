import os
import unittest


class ProductionWsgiServerTests(unittest.TestCase):
    """Regression tests ensuring the app is served by a real production WSGI
    server (waitress) rather than Flask's built-in development server, which
    prints its own "do not use in production" warning and — without
    threaded=True — only handles one request at a time by default.
    """

    def _app_py_source(self):
        app_py_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py",
        )
        with open(app_py_path) as f:
            return f.read()

    def test_main_block_uses_waitress_not_flask_dev_server(self):
        source = self._app_py_source()
        main_block = source[source.index('if __name__ == "__main__":'):]
        self.assertIn("from waitress import serve", main_block)
        self.assertIn("serve(app", main_block)
        # Check actual code lines only (not comments) for the old dev-server
        # call pattern, since "app.run()" is also mentioned in the
        # explanatory comment above the waitress import.
        code_lines = [
            line for line in main_block.splitlines()
            if not line.strip().startswith("#")
        ]
        self.assertFalse(
            any("app.run(" in line for line in code_lines),
            "app.run() (Flask dev server) call still present in __main__",
        )

    def test_waitress_is_a_declared_dependency(self):
        req_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "requirements.txt",
        )
        with open(req_path) as f:
            content = f.read()
        self.assertIn("waitress", content.lower())

    def test_waitress_is_importable(self):
        import waitress  # noqa: F401  (import itself is the assertion)


if __name__ == "__main__":
    unittest.main()
