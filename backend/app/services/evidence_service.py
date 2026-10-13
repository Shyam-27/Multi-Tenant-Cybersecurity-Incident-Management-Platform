import hashlib
import os
import re
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException, UploadFile, status

# Allowed file extensions and corresponding MIME validation
ALLOWED_EXTENSIONS = {
    # Plain text / logs
    ".log", ".txt",
    # Structured data
    ".json", ".csv",
    # Network captures
    ".pcap", ".pcapng",
    # Forensic archives
    ".zip", ".tar", ".gz", ".tgz",
}

# Magic byte signatures
MAGIC_SIGNATURES = {
    # PCAP: standard microsecond / nanosecond, little-endian and big-endian
    "pcap": [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"],
    # PCAPNG: Section Header Block (\x0a\x0d\x0d\x0a)
    "pcapng": [b"\x0a\x0d\x0d\x0a"],
    # ZIP: PK\x03\x04
    "zip": [b"\x50\x4b\x03\x04"],
    # GZIP: \x1f\x8b
    "gzip": [b"\x1f\x8b"],
}

# Dangerous executable signatures to immediately reject even if named .txt/.log
DANGEROUS_MAGIC_SIGNATURES = [
    b"MZ",                # DOS/Windows PE Executable
    b"\x7fELF",           # Linux ELF Executable
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary / Java class
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit reverse
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit reverse
    b"%!PS",              # PostScript
]


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent directory traversal or filesystem exploitation.
    Extracts strictly the basename, strips non-whitelisted characters, and enforces length.
    """
    if not filename:
        return "unnamed_evidence"
    # Extract only basename (handles Windows \ and Unix /)
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove any characters other than alphanumeric, dots, underscores, dashes
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    # Strip leading/trailing dots or spaces
    clean = clean.strip(". ")
    if not clean:
        clean = "unnamed_evidence"
    return clean[:255]


def validate_file_magic(header: bytes, ext: str) -> tuple[bool, str]:
    """
    Validate that the file header matches allowed forensic / security file types
    and does not contain executable binaries.
    """
    # 1. Check for dangerous executables
    for d_magic in DANGEROUS_MAGIC_SIGNATURES:
        if header.startswith(d_magic):
            return False, "File contains an executable binary format which is strictly prohibited"

    ext_lower = ext.lower()

    if ext_lower == ".pcap":
        for magic in MAGIC_SIGNATURES["pcap"]:
            if header.startswith(magic):
                return True, "application/vnd.tcpdump.pcap"
        return False, "Invalid PCAP magic bytes"

    if ext_lower == ".pcapng":
        for magic in MAGIC_SIGNATURES["pcapng"]:
            if header.startswith(magic):
                return True, "application/x-pcapng"
        return False, "Invalid PCAPNG magic bytes"

    if ext_lower == ".zip":
        for magic in MAGIC_SIGNATURES["zip"]:
            if header.startswith(magic):
                return True, "application/zip"
        return False, "Invalid ZIP magic bytes"

    if ext_lower in {".gz", ".tgz"}:
        for magic in MAGIC_SIGNATURES["gzip"]:
            if header.startswith(magic):
                return True, "application/gzip"
        return False, "Invalid GZIP magic bytes"

    if ext_lower == ".tar":
        # Check standard ustar magic at offset 257 if header is large enough
        if len(header) >= 262 and (header[257:262] == b"ustar" or header[257:265] == b"ustar\x0000"):
            return True, "application/x-tar"
        # Tar files may also start with header blocks without ustar in old v7 formats or be empty
        if len(header) >= 512:
            return True, "application/x-tar"
        if len(header) == 0:
            return True, "application/x-tar"
        return False, "Invalid TAR format"

    if ext_lower in {".log", ".txt"}:
        # Plain text must be valid UTF-8/ASCII without null bytes
        try:
            sample_text = header.decode("utf-8")
            if "\x00" in sample_text:
                return False, "Binary null bytes detected in plain text file"
            return True, "text/plain"
        except UnicodeDecodeError:
            return False, "File is not valid UTF-8 encoded text"

    if ext_lower == ".json":
        try:
            sample_text = header.decode("utf-8")
            if "\x00" in sample_text:
                return False, "Binary null bytes detected in JSON file"
            return True, "application/json"
        except UnicodeDecodeError:
            return False, "File is not valid UTF-8 encoded text"

    if ext_lower == ".csv":
        try:
            sample_text = header.decode("utf-8")
            if "\x00" in sample_text:
                return False, "Binary null bytes detected in CSV file"
            return True, "text/csv"
        except UnicodeDecodeError:
            return False, "File is not valid UTF-8 encoded text"

    return False, f"Unsupported file extension: {ext}"


async def save_evidence_file(
    upload_file: UploadFile,
    base_dir: str,
    tenant_id: UUID,
    incident_id: UUID,
    evidence_id: UUID,
    max_size: int = 10 * 1024 * 1024,
) -> tuple[str, str, int, str, str]:
    """
    Stream and validate evidence file:
    - Enforce file extension allowlist
    - Validate magic bytes / file headers
    - Enforce max size limit (streaming)
    - Compute SHA-256 hash incrementally
    - Store securely in `uploads/{tenant_id}/{incident_id}/{evidence_id}/{filename}`
    - Clean up file on any validation or I/O failure
    
    Returns: (stored_file_path, clean_filename, file_size_bytes, sha256_hash, mime_type)
    """
    raw_filename = upload_file.filename or "evidence"
    clean_filename = sanitize_filename(raw_filename)
    _, ext = os.path.splitext(clean_filename)

    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext}' is not permitted. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # Resolve safe destination path
    dest_dir = Path(base_dir).resolve() / str(tenant_id) / str(incident_id) / str(evidence_id)
    # Ensure dest_dir is strictly inside base_dir to prevent path traversal
    base_path_resolved = Path(base_dir).resolve()
    if base_path_resolved not in dest_dir.parents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid storage path resolution",
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    target_path = dest_dir / clean_filename

    sha256 = hashlib.sha256()
    total_size = 0
    header_bytes = bytearray()
    header_inspected = False
    detected_mime = "application/octet-stream"

    chunk_size = 64 * 1024  # 64 KB chunks

    try:
        with open(target_path, "wb") as out_f:
            while True:
                chunk = await upload_file.read(chunk_size)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size of {max_size} bytes (10 MiB)",
                    )

                sha256.update(chunk)
                out_f.write(chunk)

                if not header_inspected:
                    header_bytes.extend(chunk[: 1024 - len(header_bytes)])
                    if len(header_bytes) >= 512:
                        valid, mime_or_err = validate_file_magic(bytes(header_bytes), ext)
                        if not valid:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"File signature validation failed: {mime_or_err}",
                            )
                        detected_mime = mime_or_err
                        header_inspected = True

            # If file was smaller than 512 bytes, inspect header at end of stream
            if not header_inspected:
                valid, mime_or_err = validate_file_magic(bytes(header_bytes), ext)
                if not valid:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File signature validation failed: {mime_or_err}",
                    )
                detected_mime = mime_or_err

    except Exception:
        # Clean up target file and dir on any failure
        if target_path.exists():
            try:
                target_path.unlink()
            except OSError:
                pass
        if dest_dir.exists():
            try:
                dest_dir.rmdir()
            except OSError:
                pass
        raise

    return str(target_path), clean_filename, total_size, sha256.hexdigest(), detected_mime


def get_safe_evidence_path(base_dir: str, tenant_id: UUID, file_path_str: str) -> Path:
    """
    Ensure the file path is strictly located within the tenant's storage path.
    Prevents path traversal and cross-tenant file access.
    """
    file_path = Path(file_path_str).resolve()
    base_path = Path(base_dir).resolve()
    expected_tenant_path = base_path / str(tenant_id)

    if expected_tenant_path not in file_path.parents and file_path != expected_tenant_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found",
        )

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found on disk",
        )

    return file_path
