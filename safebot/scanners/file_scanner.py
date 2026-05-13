from __future__ import annotations

import logging
import mimetypes
import zipfile
from pathlib import Path
from typing import Iterable

from safebot.models import ScanFinding, ScanResult
from safebot.risk import result_from_findings, virustotal_finding
from safebot.scanners.virustotal import VirusTotalClient, extract_analysis_stats, file_sha256

try:
    import magic  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    magic = None

LOG = logging.getLogger(__name__)

OFFICE_EXTENSIONS = {".docm", ".docx", ".xlsm", ".xlsx", ".pptm", ".pptx"}
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".dll", ".com", ".lnk"}
ARCHIVE_EXTENSIONS = {".zip"}
PDF_JS_MARKERS = [b"/JS", b"/JavaScript", b"/OpenAction", b"/AA"]


class FileScanner:
    def __init__(
        self,
        *,
        virustotal: VirusTotalClient | None = None,
        upload_to_virustotal: bool = False,
        max_upload_mb: int = 32,
    ):
        self.virustotal = virustotal
        self.upload_to_virustotal = upload_to_virustotal
        self.max_upload_bytes = max_upload_mb * 1024 * 1024

    def scan(self, path: str | Path) -> ScanResult:
        file_path = Path(path)
        findings: list[ScanFinding] = []
        findings.extend(_mime_extension_findings(file_path))
        findings.extend(_office_macro_findings(file_path))
        findings.extend(_pdf_findings(file_path))
        findings.extend(_archive_findings(file_path))

        vt_hits: int | None = None
        vt_total: int | None = None
        if self.virustotal and self.virustotal.enabled:
            try:
                sha256 = file_sha256(file_path)
                report = self.virustotal.get_file_report(sha256)
                if report is None and self.upload_to_virustotal and file_path.stat().st_size <= self.max_upload_bytes:
                    analysis_id = self.virustotal.upload_file(file_path)
                    report = self.virustotal.wait_for_analysis(analysis_id, timeout_seconds=120)
                vt_hits, vt_total = extract_analysis_stats(report)
                vt = virustotal_finding(vt_hits, vt_total)
                if vt:
                    findings.append(vt)
            except Exception as exc:
                LOG.warning("VirusTotal file scan failed for %s: %s", file_path, exc)

        return result_from_findings(
            target=str(file_path),
            target_type="file",
            findings=findings,
            vt_hits=vt_hits,
            vt_total=vt_total,
        )


def _mime_extension_findings(path: Path) -> list[ScanFinding]:
    suffix = path.suffix.lower()
    guessed_mime, _ = mimetypes.guess_type(path.name)
    detected = _detect_mime(path)
    if not detected or not guessed_mime:
        return []

    suspicious = False
    if suffix in {".jpg", ".jpeg", ".png", ".gif", ".txt", ".pdf"} and _looks_executable(detected):
        suspicious = True
    if suffix in EXECUTABLE_EXTENSIONS and detected.startswith(("text/", "image/")):
        suspicious = True

    if suspicious:
        return [
            ScanFinding(
                code="file_extension_mismatch",
                title="文件后缀伪装",
                detail=f"文件后缀与 MIME 类型不一致：{suffix or '(无后缀)'} / {detected}",
                points=50,
                source="file_rules",
                metadata={"suffix": suffix, "mime": detected, "guessed_mime": guessed_mime},
            )
        ]
    return []


def _detect_mime(path: Path) -> str:
    if magic is not None:
        try:
            return str(magic.from_file(str(path), mime=True))
        except Exception as exc:
            LOG.debug("magic MIME detection failed for %s: %s", path, exc)
    with path.open("rb") as file:
        header = file.read(16)
    if header.startswith(b"MZ"):
        return "application/x-msdownload"
    if header.startswith(b"%PDF"):
        return "application/pdf"
    if header.startswith(b"PK\x03\x04"):
        return "application/zip"
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def _looks_executable(mime: str) -> bool:
    return mime in {"application/x-msdownload", "application/vnd.microsoft.portable-executable"} or "executable" in mime


def _office_macro_findings(path: Path) -> list[ScanFinding]:
    if path.suffix.lower() not in OFFICE_EXTENSIONS or not zipfile.is_zipfile(path):
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except Exception as exc:
        LOG.debug("Office zip inspection failed for %s: %s", path, exc)
        return []
    if any(name.lower().endswith("vbaproject.bin") for name in names):
        return [
            ScanFinding(
                code="office_macro",
                title="Office 宏",
                detail="Office 文件包含 vbaProject.bin 宏代码",
                points=35,
                source="file_rules",
            )
        ]
    return []


def _pdf_findings(path: Path) -> list[ScanFinding]:
    if path.suffix.lower() != ".pdf":
        return []
    try:
        data = path.read_bytes()[:5_000_000]
    except Exception as exc:
        LOG.debug("PDF inspection failed for %s: %s", path, exc)
        return []
    hits = [marker.decode("ascii") for marker in PDF_JS_MARKERS if marker in data]
    if hits:
        return [
            ScanFinding(
                code="pdf_javascript",
                title="PDF 嵌入脚本",
                detail="PDF 包含嵌入执行标签：" + "、".join(hits),
                points=30,
                source="file_rules",
                metadata={"markers": hits},
            )
        ]
    return []


def _archive_findings(path: Path) -> list[ScanFinding]:
    if path.suffix.lower() not in ARCHIVE_EXTENSIONS or not zipfile.is_zipfile(path):
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except Exception as exc:
        LOG.debug("Archive inspection failed for %s: %s", path, exc)
        return []
    executables = list(_executable_members(names))
    if executables:
        return [
            ScanFinding(
                code="archive_contains_executable",
                title="压缩包含可执行文件",
                detail="压缩包内包含可执行文件：" + "、".join(executables[:5]),
                points=45,
                source="file_rules",
                metadata={"members": executables},
            )
        ]
    return []


def _executable_members(names: Iterable[str]) -> Iterable[str]:
    for name in names:
        suffix = Path(name).suffix.lower()
        if suffix in EXECUTABLE_EXTENSIONS:
            yield name
