import os
import tempfile
import unittest


def _reload_app(**env):
    import importlib
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    import auth
    import db
    import app
    from settings.store import get_store
    importlib.reload(auth)
    db_mod = importlib.reload(db)
    db_mod.init_db()
    get_store(db_module=db_mod, force_new=True)
    return importlib.reload(app)


class BuildIdentityTests(unittest.TestCase):
    """The version string only moves on a release, so it cannot tell two
    builds apart — every redeploy between releases reported "v1.3.0" and
    there was no way to see which code was actually running. The commit is
    what identifies a build.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.app_module = _reload_app(
            DOMAINLENS_DB=os.path.join(self.tempdir.name, "b.db"),
            DOMAINLENS_DISABLE_SCHEDULER="1",
            AUTH_LOCAL_ENABLED="0",
            OAUTH_ENABLED="0",
            DOMAINLENS_SECRET_KEY="test-secret",
            DOMAINLENS_GIT_SHA="abcdef1234567890",
            DOMAINLENS_IMAGE="itsraynor/domainlens",
            DOMAINLENS_IMAGE_TAG="1.3.0",
        )
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "AUTH_LOCAL_ENABLED",
                    "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY", "DOMAINLENS_GIT_SHA",
                    "DOMAINLENS_IMAGE", "DOMAINLENS_IMAGE_TAG"):
            os.environ.pop(key, None)

    def test_footer_shows_the_short_commit(self):
        body = self.client.get("/").data.decode()
        self.assertIn("commit-chip", body)
        self.assertIn("abcdef1", body)

    def test_commit_links_to_github(self):
        body = self.client.get("/").data.decode()
        self.assertIn("github.com/ItsRaYnor/DomainLens/commit/abcdef123456", body)

    def test_settings_shows_full_commit_and_image_tag(self):
        body = self.client.get("/admin/settings").data.decode()
        self.assertIn("abcdef123456", body)
        self.assertIn("itsraynor/domainlens:1.3.0", body)

    def test_api_version_exposes_the_revision(self):
        data = self.client.get("/api/version").get_json()
        self.assertEqual(data["git_revision"], "abcdef123456")


class BuildIdentityWithoutRevisionTests(unittest.TestCase):
    """An image built without the git SHA baked in must degrade gracefully
    rather than render a broken commit link."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        # A .git directory is present in a source checkout, so point the
        # revision lookup at nothing by clearing both env vars and relying on
        # the explicit assertion below rather than assuming it is empty.
        self.app_module = _reload_app(
            DOMAINLENS_DB=os.path.join(self.tempdir.name, "b2.db"),
            DOMAINLENS_DISABLE_SCHEDULER="1",
            AUTH_LOCAL_ENABLED="0",
            OAUTH_ENABLED="0",
            DOMAINLENS_SECRET_KEY="test-secret",
            DOMAINLENS_GIT_SHA=None,
            GIT_COMMIT=None,
        )
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER", "AUTH_LOCAL_ENABLED",
                    "OAUTH_ENABLED", "DOMAINLENS_SECRET_KEY"):
            os.environ.pop(key, None)

    def test_settings_page_renders_without_a_revision(self):
        from unittest import mock
        with mock.patch("version.get_git_revision", return_value=None):
            body = self.client.get("/admin/settings").data.decode()
        self.assertIn("Build:", body)
        self.assertIn("unknown", body)
        self.assertNotIn("/commit/None", body)

    def test_footer_omits_the_chip_without_a_revision(self):
        from unittest import mock
        with mock.patch("version.get_git_revision", return_value=None):
            body = self.client.get("/").data.decode()
        self.assertNotIn("/commit/None", body)


if __name__ == "__main__":
    unittest.main()


class RenameCompletenessTests(unittest.TestCase):
    """The tool was renamed from NetProbe to DomainLens, and the operator was
    given no fallback: the environment variables, the image and the database
    filename all changed at once. A leftover `NETPROBE_` read is therefore not
    a cosmetic blemish — it is a setting the operator has moved that the code
    still looks for under the old name, and it fails silently by quietly using
    a default.
    """

    SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}
    SKIP_SUFFIXES = {".db", ".db-wal", ".db-shm", ".png", ".jpg", ".ico", ".pyc"}

    # Two files name the old tool on purpose, and both would be useless if
    # they did not. Listed one by one rather than skipping docs/ wholesale, so
    # a third file cannot quietly join them.
    ALLOWED = {
        "docs/MIGRATION_0.0.1.md",   # maps every old variable to its new name
        "CLAUDE.md",                 # records why the version was reset
    }

    def _tracked_files(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            if path.suffix in self.SKIP_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            # This file names the old string on purpose, to look for it.
            if path.name == pathlib.Path(__file__).name or relative in self.ALLOWED:
                continue
            yield path, root

    def test_the_old_name_survives_nowhere(self):
        offenders = []
        for path, root in self._tracked_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if "netprobe" in line.lower():
                    offenders.append(f"{path.relative_to(root)}:{lineno}")
        self.assertEqual(offenders, [], "the old name is still referenced")

    def test_the_version_restarted(self):
        # The rename to DomainLens reset the count to the 0.0.x era rather than
        # carrying NetProbe's old numbering forward. Assert it stayed in that
        # era and is a valid, non-regressed semver — not a fixed 0.0.1, which
        # would break on every patch bump the versioning policy requires.
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        raw = (root / "VERSION").read_text(encoding="utf-8").strip()
        parts = raw.split(".")
        self.assertEqual(len(parts), 3, f"VERSION is not semver: {raw!r}")
        major, minor, patch = (int(p) for p in parts)
        self.assertEqual(major, 0, "still in the post-rename 0.0.x era")
        self.assertGreaterEqual((major, minor, patch), (0, 0, 1),
                                "VERSION must never go below the reset point")

    def test_the_environment_prefix_is_the_new_one(self):
        import version
        os.environ["DOMAINLENS_VERSION"] = "9.9.9"
        try:
            version.get_version.cache_clear()
            self.assertEqual(version.get_version(), "9.9.9")
        finally:
            os.environ.pop("DOMAINLENS_VERSION", None)
            version.get_version.cache_clear()
