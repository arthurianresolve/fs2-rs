import tempfile
import unittest
from pathlib import Path

from validate_compatibility import (
    CONSUMER,
    EXPECTED_CONSUMER_SHA256,
    compatibility_packages,
    consumer_digest,
    validate_frozen_consumer,
)


class CompatibilityValidationTests(unittest.TestCase):
    def test_consumer_digest_is_frozen(self):
        self.assertEqual(consumer_digest(CONSUMER), EXPECTED_CONSUMER_SHA256)
        self.assertEqual(validate_frozen_consumer(CONSUMER), EXPECTED_CONSUMER_SHA256)

    def test_rejects_changed_consumer(self):
        with tempfile.TemporaryDirectory(prefix="fs2-compatibility-test-") as temporary:
            path = Path(temporary) / "v04_consumer.rs"
            path.write_bytes(CONSUMER.read_bytes() + b"\n")

            with self.assertRaises(SystemExit):
                validate_frozen_consumer(path)

    def test_discovers_compatibility_packages_from_workspace_metadata(self):
        packages = compatibility_packages()

        self.assertEqual(
            [(package.name, package.edition) for package in packages],
            [
                ("fs2-compat-edition-2015", "2015"),
                ("fs2-compat-edition-2018", "2018"),
                ("fs2-compat-edition-2021", "2021"),
                ("fs2-compat-edition-2024", "2024"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
