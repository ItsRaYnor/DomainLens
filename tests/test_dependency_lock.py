"""Every package the image installs is pinned, with its hashes.

requirements.txt pinned the direct dependencies only. Flask's werkzeug and
jinja2, requests' urllib3, idna and certifi, cryptography's cffi: each build
took whatever was newest that day, so the image could hold versions CI never
tested or audited, and a package replaced on the index would have been
installed without anyone noticing. The lock now holds all of them, each with
its hashes, and the image refuses anything that does not match.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", re.M)


def _entries(text):
    """{name: block} for each pinned package in a pip-compile lock."""
    out = {}
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text):
        match = _PIN.match(block.strip())
        if match:
            out[match.group(1).lower().replace("_", "-")] = block
    return out


class LockTests(unittest.TestCase):
    def setUp(self):
        self.lock = ROOT.joinpath("requirements.txt").read_text(encoding="utf-8")
        self.direct = ROOT.joinpath("requirements.in").read_text(encoding="utf-8")

    def test_every_package_in_the_lock_carries_a_hash(self):
        entries = _entries(self.lock)
        self.assertGreater(len(entries), 20, "the lock should hold the transitive packages too")
        missing = sorted(name for name, block in entries.items() if "--hash=sha256:" not in block)
        self.assertEqual([], missing)

    def test_every_direct_dependency_is_in_the_lock_at_its_version(self):
        locked = {name: _PIN.match(block.strip()).group(2) for name, block in _entries(self.lock).items()}
        for name, version in _PIN.findall(self.direct):
            key = name.lower().replace("_", "-")
            self.assertEqual(version, locked.get(key), f"{name} in requirements.in vs the lock")

    def test_the_transitive_packages_are_pinned_too(self):
        locked = _entries(self.lock)
        for name in ("werkzeug", "jinja2", "urllib3", "idna", "certifi", "cffi"):
            self.assertIn(name, locked)

    def test_the_image_and_ci_install_with_the_hashes_checked(self):
        docker = ROOT.joinpath("Dockerfile").read_text(encoding="utf-8")
        self.assertIn("pip install --no-cache-dir --require-hashes -r requirements.txt", docker)
        ci = ROOT.joinpath(".github", "workflows", "tests.yml").read_text(encoding="utf-8")
        self.assertIn("pip install --require-hashes -r requirements.txt", ci)
        self.assertIn("pip-audit -r requirements.txt --require-hashes --strict", ci)

    def test_the_image_itself_is_scanned_before_it_is_published(self):
        ci = ROOT.joinpath(".github", "workflows", "tests.yml").read_text(encoding="utf-8")
        self.assertIn("docker build -t domainlens:ci .", ci)
        self.assertRegex(ci, r"trivy:latest image \\\n\s+--scanners vuln .*--exit-code 1 domainlens:ci")

    def test_updates_arrive_for_packages_base_image_and_actions(self):
        dependabot = ROOT.joinpath(".github", "dependabot.yml").read_text(encoding="utf-8")
        for ecosystem in ("pip", "docker", "github-actions"):
            self.assertIn(f"package-ecosystem: {ecosystem}", dependabot)


if __name__ == "__main__":
    unittest.main()
