import tempfile
import unittest
from pathlib import Path

from validate_compatibility import (
    CONSUMER,
    EXPECTED_CONSUMER_SHA256,
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


if __name__ == "__main__":
    unittest.main()
