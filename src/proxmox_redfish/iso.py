#!/usr/bin/env python3
"""ISO pipeline — download, upload, and deduplication helpers for Proxmox storage."""

import hashlib
import logging
import os
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple

import requests
from proxmoxer import ProxmoxAPI

logger = logging.getLogger("proxmox-redfish")

PROXMOX_ISO_STORAGE = os.getenv("PROXMOX_ISO_STORAGE", "local")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# File locks for individual ISO files
iso_file_locks: Dict[str, threading.Lock] = {}
iso_file_locks_lock = threading.Lock()

# _get_storage_node is imported here via a controlled circular import:
# proxmox_redfish.py defines _get_storage_node before importing this module,
# so it is available in sys.modules by the time this line executes.
from proxmox_redfish.proxmox_redfish import _get_storage_node  # noqa: E402


def get_file_lock(filename: str) -> threading.Lock:
    """
    Get or create a lock for a specific ISO file.
    This ensures only one thread can modify a specific ISO file at a time.
    """
    with iso_file_locks_lock:
        if filename not in iso_file_locks:
            iso_file_locks[filename] = threading.Lock()
        return iso_file_locks[filename]


def _wait_for_task_completion(
    proxmox: ProxmoxAPI, task_id: str, node_name: str, poll_interval: int = 2, timeout: int = 3600
) -> None:
    """Wait for a Proxmox task to finish successfully."""
    logger.info("Waiting for task completion: %s", task_id)
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError(f"Timed out waiting for task {task_id} after {timeout}s")
        status = proxmox.nodes(node_name).tasks(task_id).status.get()
        if status is None:
            raise Exception(f"Failed to get task status for {task_id}")
        if status.get("status") == "stopped":
            if status.get("exitstatus") == "OK":
                logger.info("Task completed successfully: %s", task_id)
                return
            raise Exception(f"Task failed: {status}")
        time.sleep(poll_interval)


def _get_storage_details(proxmox: ProxmoxAPI, storage_node: str) -> Dict[str, Any]:
    """Fetch metadata for the configured ISO storage."""
    storage_info = proxmox.nodes(storage_node).storage(PROXMOX_ISO_STORAGE).get()
    if isinstance(storage_info, dict):
        return storage_info
    return {}


def _storage_supports_iso(storage_info: Dict[str, Any]) -> bool:
    """Check whether the configured storage advertises ISO content support."""
    content_types = storage_info.get("content")
    if isinstance(content_types, str):
        return "iso" in {entry.strip() for entry in content_types.split(",")}
    if isinstance(content_types, list):
        return "iso" in content_types
    return False


def _list_iso_storage_content(proxmox: ProxmoxAPI, storage_node: str) -> list[Dict[str, Any]]:
    """List ISO content entries on the configured storage."""
    content_api = proxmox.nodes(storage_node).storage(PROXMOX_ISO_STORAGE).content
    try:
        entries = content_api.get(content="iso")
    except Exception:
        entries = content_api.get()
    return entries if isinstance(entries, list) else []


def _find_iso_entry(entries: list[Dict[str, Any]], filename: str) -> Optional[Dict[str, Any]]:
    """Locate an ISO entry by its filename on the configured storage."""
    target_volid = f"{PROXMOX_ISO_STORAGE}:iso/{filename}"
    for entry in entries:
        if entry.get("volid") == target_volid:
            return entry
    return None


def _download_iso_to_file(url: str, target_path: str) -> Tuple[str, int]:
    """Download an ISO URL to a local temp file while computing its SHA-256."""
    logger.info("Downloading ISO from URL: %s", url)
    response = requests.get(url, stream=True, timeout=600, verify=VERIFY_SSL)
    response.raise_for_status()

    checksum = hashlib.sha256()
    size = 0
    with open(target_path, "wb") as handle:
        for chunk in response.iter_content(16 << 20):
            if not chunk:
                continue
            handle.write(chunk)
            checksum.update(chunk)
            size += len(chunk)

    return checksum.hexdigest(), size


def _upload_iso_file(proxmox: ProxmoxAPI, file_path: str, storage_node: str) -> None:
    """Upload an ISO file to the configured Proxmox storage via API."""
    upload_api = proxmox.nodes(storage_node).storage(PROXMOX_ISO_STORAGE).upload
    with open(file_path, "rb") as iso_file:
        try:
            task_id = upload_api.post(content="iso", filename=iso_file)
        except TypeError:
            iso_file.seek(0)
            task_id = upload_api.post(content="iso", filename=os.path.basename(file_path), file=iso_file)

    _wait_for_task_completion(proxmox, task_id, storage_node)


def _ensure_iso_available(proxmox: ProxmoxAPI, url_or_volid: str, node_name: Optional[str] = None) -> str:
    """
    Return a storage:iso/… volid, downloading + uploading if needed.
    Supports HTTP/S URLs and local storage references.
    Implements hash-based conflict handling and thread-safe concurrent access.

    Args:
        proxmox: ProxmoxAPI instance
        url_or_volid: HTTP/S URL or storage:iso/... reference
        node_name: Proxmox node for storage operations (resolved automatically if omitted)

    Returns:
        str: storage:iso/filename reference for Proxmox
    """
    # Already looks like "storage:iso/…" → nothing to do
    if ":iso/" in url_or_volid:
        return url_or_volid

    # Check if it's a URL (http/https)
    if url_or_volid.startswith(("http://", "https://")):
        if PROXMOX_ISO_STORAGE == "none":
            raise ValueError("ISO downloads are disabled (PROXMOX_ISO_STORAGE=none)")

        logger.info("Processing ISO from URL: %s", url_or_volid)

        # Extract filename from URL, handling query parameters
        fname = os.path.basename(url_or_volid.split("?", 1)[0])
        if not fname.endswith(".iso"):
            fname += ".iso"  # Ensure .iso extension

        storage_node = _get_storage_node(proxmox, node_name)
        storage_info = _get_storage_details(proxmox, storage_node)
        if storage_info and not _storage_supports_iso(storage_info):
            raise ValueError(f"Storage {PROXMOX_ISO_STORAGE} does not support ISO content")

        # Get file-specific lock to prevent concurrent access to the same ISO
        file_lock = get_file_lock(fname)

        with file_lock:
            logger.info("Acquired lock for ISO file: %s", fname)
            entries = _list_iso_storage_content(proxmox, storage_node)
            existing_entry = _find_iso_entry(entries, fname)

            # Fast path: if the ISO already exists, check Content-Length via HEAD
            # before downloading the full file.
            if existing_entry:
                try:
                    head_resp = requests.head(url_or_volid, timeout=30, verify=VERIFY_SSL, allow_redirects=True)
                    remote_size = int(head_resp.headers.get("Content-Length", -1))
                    if remote_size != -1 and remote_size == existing_entry.get("size"):
                        logger.info(
                            "ISO already present with matching size (HEAD check), reusing %s",
                            existing_entry.get("volid"),
                        )
                        return existing_entry["volid"]
                except Exception:
                    pass  # Fall through to full download for hash comparison

            with tempfile.TemporaryDirectory(prefix="proxmox-redfish-iso-") as tmp_dir:
                download_path = os.path.join(tmp_dir, fname)
                downloaded_hash_hex, downloaded_size = _download_iso_to_file(url_or_volid, download_path)

                if existing_entry:
                    existing_size = existing_entry.get("size")
                    if existing_size == downloaded_size:
                        logger.info("ISO already present with matching size, reusing %s", existing_entry.get("volid"))
                        return existing_entry["volid"]

                    logger.info("Existing ISO name conflict detected, using hash suffix")
                    name_without_ext, ext = os.path.splitext(fname)
                    fname = f"{name_without_ext}_{downloaded_hash_hex[:8]}{ext}"
                    renamed_path = os.path.join(tmp_dir, fname)
                    os.replace(download_path, renamed_path)
                    download_path = renamed_path

                    existing_entry = _find_iso_entry(_list_iso_storage_content(proxmox, storage_node), fname)
                    if existing_entry:
                        logger.info("Hash-suffixed ISO already present, reusing %s", existing_entry.get("volid"))
                        return existing_entry["volid"]

                try:
                    logger.info("Uploading ISO to storage %s via Proxmox API", PROXMOX_ISO_STORAGE)
                    _upload_iso_file(proxmox, download_path, storage_node)
                except Exception as upload_error:
                    existing_entry = _find_iso_entry(_list_iso_storage_content(proxmox, storage_node), fname)
                    if existing_entry:
                        logger.info("ISO became available during upload retry window, reusing %s", existing_entry.get("volid"))
                        return existing_entry["volid"]
                    raise Exception(f"API upload failed for {fname}: {upload_error}") from upload_error

            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
            logger.info("ISO available as: %s", volid)
            return volid

    # Not a URL and not a storage reference - return as-is (Proxmox will handle validation)
    logger.warning("Unknown ISO format: %s", url_or_volid)
    return url_or_volid
