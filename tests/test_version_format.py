import pathlib
import re
import unittest

import version


VERSION_FILE = pathlib.Path(__file__).resolve().parent.parent / "VERSION"
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class VersionFormatTests(unittest.TestCase):
    """parse_semver() truncates to three components, so a four-part version
    like 1.3.1.1 compares equal to 1.3.1.9 and update detection silently
    stops working. Three-part patch bumps (1.3.0 -> 1.3.1 -> 1.3.2) already
    give small increments; the guard exists so a fourth component cannot be
    introduced without this failing loudly.
    """

    def test_version_file_is_three_part_semver(self):
        raw = VERSION_FILE.read_text(encoding="utf-8").strip()
        self.assertRegex(
            raw, _SEMVER_RE,
            f"VERSION must be MAJOR.MINOR.PATCH; got {raw!r}. A fourth "
            "component is silently ignored when comparing versions.",
        )

    def test_four_part_versions_are_indistinguishable(self):
        # Documents exactly why the guard above exists.
        self.assertEqual(version.parse_semver("1.3.1.1"), version.parse_semver("1.3.1.9"))
        self.assertFalse(version.is_newer("1.3.1.9", "1.3.1.1"))

    def test_patch_bumps_compare_correctly(self):
        self.assertTrue(version.is_newer("1.3.1", "1.3.0"))
        self.assertTrue(version.is_newer("1.3.10", "1.3.9"))
        self.assertTrue(version.is_newer("1.4.0", "1.3.99"))
        self.assertFalse(version.is_newer("1.3.0", "1.3.1"))

    def test_ci_tag_pattern_matches_this_version(self):
        """docker-publish.yml builds on tags matching v*.*.* — a version the
        workflow would not fire on is worse than useless."""
        raw = VERSION_FILE.read_text(encoding="utf-8").strip()
        self.assertEqual(len(raw.split(".")), 3)


if __name__ == "__main__":
    unittest.main()
