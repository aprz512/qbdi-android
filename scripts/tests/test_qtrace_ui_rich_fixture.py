import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "qtrace-ui" / "tools" / "generate_rich_performance_fixture.py"


def load_generator():
    if str(MODULE_PATH.parent) not in sys.path:
        sys.path.insert(0, str(MODULE_PATH.parent))
    spec = importlib.util.spec_from_file_location("rich_performance_fixture", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rich fixture generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RichFixtureTests(unittest.TestCase):
    def test_fixed_semantic_fingerprint_and_real_typed_records(self):
        import hashlib
        import struct

        generator = load_generator()
        corpus = generator._raw_corpus()
        self.assertEqual(generator.RAW_SEMANTIC_SHA256, hashlib.sha256(corpus).hexdigest())
        self.assertEqual(b"QTRB", corpus[:4])
        kinds = []
        cursor = 16
        while cursor < len(corpus):
            kind, _flags, size = struct.unpack_from("<HHI", corpus, cursor)
            kinds.append(kind)
            cursor += 8 + size
        self.assertEqual(len(corpus), cursor)
        self.assertEqual(100_006, len(kinds))
        self.assertEqual(60_000, kinds.count(4))
        self.assertEqual(20_000, kinds.count(5))
        self.assertEqual(20_000, kinds.count(6))
        self.assertEqual(0, kinds.count(0x8001))


if __name__ == "__main__":
    unittest.main()
