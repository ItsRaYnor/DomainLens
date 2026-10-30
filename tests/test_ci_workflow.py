"""The published image must never be built from a commit whose tests failed.

docker-publish.yml pushed `latest` on every commit to main with no test run
in front of it, so a regression reached every installation that pulls
`latest` before anyone had seen it fail.
"""

import os
import re
import shutil
import subprocess
import tempfile
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


class ReleaseNotesTests(unittest.TestCase):
    """A release said only "Full Changelog" and a compare link: whoever
    pulled a new tag had to read commits to learn what it changed."""

    def test_a_release_carries_the_notes_written_for_its_version(self):
        publish = _read("docker-publish.yml")
        self.assertIn('if [ -f "docs/releases/${VERSION}.md" ]; then', publish)
        self.assertEqual(2, publish.count('"${notes[@]}" --generate-notes'))

    def test_the_current_version_has_its_notes(self):
        with open(os.path.join(_ROOT, "VERSION"), encoding="utf-8") as handle:
            version = handle.read().strip()
        self.assertTrue(os.path.isfile(os.path.join(_ROOT, "docs", "releases", f"{version}.md")),
                        f"docs/releases/{version}.md is missing: the release would have no notes")


def _steps(workflow):
    """{name: text} for each step of a workflow, split on its `- name:` lines."""
    parts = re.split(r"\n      - name: ", workflow)[1:]
    return {part.split("\n", 1)[0].strip(): part for part in parts}


def _run_block(step):
    """The shell script of a step's `run: |` block, dedented."""
    lines = step.split("run: |\n", 1)[1].split("\n")
    body = []
    for line in lines:
        if line.strip() and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body)


class PublishedVersionIsNotRebuiltTests(unittest.TestCase):
    """A Dependabot merge to main, without a new VERSION, pushed a new image
    under the number already released: `domainlens:0.1.20` would no longer be
    what was released as 0.1.20, and a rollback to it would land elsewhere."""

    _PUBLISHING = ("Set up Docker Buildx", "Log in to Docker Hub", "Compute image tags", "Build and push",
                   "Update Docker Hub description", "Tag and release this version")

    def test_every_publishing_step_waits_for_the_check(self):
        steps = _steps(_read("docker-publish.yml"))
        self.assertIn("Is this version published already", steps)
        for name in self._PUBLISHING:
            self.assertIn("steps.published.outputs.done != 'true'", steps[name].split("\n        uses:")[0]
                          .split("\n        run:")[0], f"'{name}' still runs for a version that is published")

    def _check(self, release_exists, tag_exists):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not installed")
        script = _run_block(_steps(_read("docker-publish.yml"))["Is this version published already"])
        with tempfile.TemporaryDirectory() as tmp:
            for tool, exists in (("gh", release_exists), ("git", tag_exists)):
                path = os.path.join(tmp, tool)
                with open(path, "w", newline="\n") as handle:
                    handle.write(f"#!/bin/sh\nexit {0 if exists else 2}\n")
                os.chmod(path, 0o755)
            out = os.path.join(tmp, "output")
            env = {**os.environ, "PATH": tmp + os.pathsep + os.environ.get("PATH", ""),
                   "VERSION": "0.1.20", "GITHUB_OUTPUT": out}
            done = subprocess.run([bash, "-c", f'export PATH="$(cygpath -u "{tmp}" 2>/dev/null || echo "{tmp}"):$PATH"\n'
                                   + script], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, done.returncode, done.stderr)
            with open(out, encoding="utf-8") as handle:
                return handle.read().strip()

    def test_a_released_version_is_not_built_again(self):
        self.assertEqual("done=true", self._check(release_exists=True, tag_exists=False))

    def test_a_tag_without_a_release_counts_as_published(self):
        self.assertEqual("done=true", self._check(release_exists=False, tag_exists=True))

    def test_a_new_version_is_built(self):
        self.assertEqual("done=false", self._check(release_exists=False, tag_exists=False))


if __name__ == "__main__":
    unittest.main()
