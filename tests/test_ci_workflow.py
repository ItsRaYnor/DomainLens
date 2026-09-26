"""The published image must never be built from a commit whose tests failed.

docker-publish.yml pushed `latest` on every commit to main with no test run
in front of it, so a regression reached every installation that pulls
`latest` before anyone had seen it fail.
"""

import os
import re
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORKFLOWS = os.path.join(_ROOT, ".github", "workflows")


def _read(name):
    with open(os.path.join(_WORKFLOWS, name), encoding="utf-8") as handle:
        return handle.read()


class PublishWaitsForTestsTests(unittest.TestCase):
    def test_the_build_job_needs_the_test_job(self):
        publish = _read("docker-publish.yml")
        build = publish.split("build-and-push:", 1)[1]
        self.assertRegex(build.split("steps:", 1)[0], r"needs:\s*tests",
                         "build-and-push can publish without the tests passing")

    def test_the_test_job_is_the_reusable_test_workflow(self):
        publish = _read("docker-publish.yml")
        self.assertIn("uses: ./.github/workflows/tests.yml", publish)
        self.assertIn("workflow_call", _read("tests.yml"),
                      "tests.yml cannot be called, so the publish gate would not start")

    def test_the_test_workflow_actually_runs_pytest(self):
        self.assertTrue(re.search(r"python -m pytest", _read("tests.yml")))

    def test_dependencies_are_audited_before_publishing(self):
        """A scanner shipped with a known-vulnerable dependency is the first
        thing a customer's own scanner reports."""
        self.assertIn("pip-audit", _read("tests.yml"))


if __name__ == "__main__":
    unittest.main()
