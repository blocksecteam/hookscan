import pathlib
import unittest

from uniscan.__main__ import compile_standard_json
from uniscan.detectors.all_detectors import all_detectors_dict
from uniscan.uniscan import Uniscan


class TestAll(unittest.TestCase):
    def _run(self, directory: str, unsafe: bool):
        directory_path = pathlib.Path(__file__).resolve().parent / directory
        for file_path in directory_path.iterdir():
            if not file_path.name.endswith(".sol"):
                continue

            with self.subTest(path=file_path):
                with open(file_path) as f:
                    sol = f.read()
                std_input_json = {"language": "Solidity", "sources": {file_path.name: {"content": sol}}}
                std_json = compile_standard_json(std_input_json)

                detector_name = file_path.stem

                uniscan = Uniscan(std_json)
                uniscan.register_detectors([all_detectors_dict[detector_name]])
                detector_results = uniscan.detect(str_key=True)["detection_results"][detector_name]
                del uniscan

                if unsafe:
                    self.assertTrue(
                        len(detector_results) != 0,
                        msg=f"{detector_name} misses vulnerabilities in contract {file_path}.",
                    )
                else:
                    self.assertTrue(
                        len(detector_results) == 0,
                        msg=f"{detector_name} raises unexpected vulnerabilities in contract {file_path}.",
                    )

    def test_safe(self):
        self._run(directory="safe", unsafe=False)

    def test_unsafe(self):
        self._run(directory="unsafe", unsafe=True)


if __name__ == "__main__":
    unittest.main()
