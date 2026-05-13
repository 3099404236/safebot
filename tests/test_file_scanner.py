import tempfile
import unittest
import zipfile
from pathlib import Path

from safebot.scanners.file_scanner import FileScanner


class FileScannerTest(unittest.TestCase):
    def test_pdf_javascript_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pdf"
            path.write_bytes(b"%PDF-1.7\n/JavaScript /OpenAction\n")
            result = FileScanner().scan(path)
            self.assertTrue(any(item.code == "pdf_javascript" for item in result.findings))

    def test_zip_contains_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("run.exe", b"MZ")
            result = FileScanner().scan(path)
            self.assertTrue(any(item.code == "archive_contains_executable" for item in result.findings))

    def test_office_macro_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.docm"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("word/vbaProject.bin", b"macro")
            result = FileScanner().scan(path)
            self.assertTrue(any(item.code == "office_macro" for item in result.findings))


if __name__ == "__main__":
    unittest.main()
