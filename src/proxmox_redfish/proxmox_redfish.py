#!/usr/bin/env python3
"""
Proxmox Redfish Daemon

A Redfish API daemon for managing Proxmox VMs, providing a standardized interface
for VM operations through the Redfish protocol.
"""

import argparse
import base64
import binascii
import json
import logging
import logging.handlers
import os
import secrets
import socketserver
import ssl
import sys
import time
from typing import Any, Dict, Optional, Tuple, Union

# When run as a script (ExecStart=.../python proxmox_redfish.py), sys.path[0] is
# the proxmox_redfish/ directory, which makes `proxmox_redfish` resolve to
# proxmox_redfish.py (a module) rather than the package directory.  Ensure the
# src/ parent is in sys.path so sub-module imports (proxmox_redfish.iso, etc.)
# resolve to the package directory.
_pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_parent not in sys.path:
    sys.path.insert(0, _pkg_parent)

import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

# Configure logging to send to system journal
# Logging configuration with configurable levels
logger = logging.getLogger("proxmox-redfish")

# Get logging level from environment variable
# Valid levels: CRITICAL, ERROR, WARNING, INFO, DEBUG
# Default to INFO for production use
log_level_str = os.getenv("REDFISH_LOG_LEVEL", "INFO").upper()
log_level_map = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

# Validate and set logging level
if log_level_str in log_level_map:
    log_level = log_level_map[log_level_str]
else:
    print(f"Warning: Invalid REDFISH_LOG_LEVEL '{log_level_str}', using INFO")
    log_level = logging.INFO

# Check if logging is enabled at all
logging_enabled = os.getenv("REDFISH_LOGGING_ENABLED", "true").lower() == "true"

if logging_enabled:
    # Configure logging with the specified level
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s:%(lineno)d: %(message)s",
        handlers=[logging.handlers.SysLogHandler(address="/dev/log")],
    )
    logger.setLevel(log_level)
    logger.info("Proxmox-Redfish daemon started with log level: %s", log_level_str)
else:
    logger.handlers = [logging.NullHandler()]
    print("Logging disabled via REDFISH_LOGGING_ENABLED=false")

# Proxmox configuration from environment variables with fallbacks
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "pve-node-hostname")
PROXMOX_USER = os.getenv("PROXMOX_USER", "username")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "password")
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "").strip()
PROXMOX_API_PORT = os.getenv("PROXMOX_API_PORT", "8006")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
# ISO storage configuration - specifies the Proxmox storage used for ISO uploads
PROXMOX_ISO_STORAGE = os.getenv("PROXMOX_ISO_STORAGE", "local")
# Legacy support for OCP_ZTP_AUTOLOAD (deprecated)
AUTOLOAD = os.getenv("OCP_ZTP_AUTOLOAD", "false").lower() == "true" or PROXMOX_ISO_STORAGE != "none"

# SSL certificate configuration
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "/opt/proxmox-redfish/config/ssl/server.crt")
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", "/opt/proxmox-redfish/config/ssl/server.key")
SSL_CA_FILE = os.getenv("SSL_CA_FILE", "/opt/proxmox-redfish/config/ssl/ca.crt")  # Optional CA bundle

# Options
# -A <Authn>, --Auth <Authn> -- Authentication type to use:  Authn={ None | Basic | Session (default) }
# -S <Secure>, --Secure=<Secure> -- <Secure>={ None | Always (default) }
AUTH = "Basic"
SECURE = "Always"

# Session TTL in seconds (1 hour)
SESSION_TTL_SECONDS = 3600

# Proxmox device limits per type: (device_type, max_count)
DISK_DEVICE_RANGES = [("scsi", 31), ("sata", 6), ("ide", 4), ("virtio", 16)]
NET_DEVICE_COUNT = 32  # net0–net31

# In-memory session store
sessions: Dict[str, Dict[str, Any]] = {}
_last_session_purge: float = 0.0

def handle_proxmox_error(
    operation: str, exception: Exception, vm_id: Optional[Union[str, int]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Handle Proxmox API exceptions and return a Redfish-compliant error response.

    Args:
        operation (str): The operation being performed (e.g., "Power On", "Reboot").
        exception (Exception): The exception raised by ProxmoxAPI (typically ResourceException).
        vm_id (int, optional): The VM ID, if applicable, for more specific error messages.

    Returns:
        tuple: (response_dict, status_code) for Redfish response.
    """
    if not isinstance(exception, ResourceException):
        # Handle unexpected non-Proxmox errors
        return {
            "error": {
                "code": "Base.1.0.GeneralError",
                "message": f"Unexpected error during {operation}: {str(exception)}",
                "@Message.ExtendedInfo": [
                    {"MessageId": "Base.1.0.GeneralError", "Message": "An unexpected error occurred on the server."}
                ],
            }
        }, 500

    # Extract Proxmox error details
    status_code = exception.status_code
    message = str(exception)
    vm_context = f" for VM {vm_id}" if vm_id is not None else ""

    # Map Proxmox status codes to Redfish error codes
    if status_code == 403:
        redfish_error_code = "Base.1.0.InsufficientPrivilege"
        extended_info = [
            {
                "MessageId": "Base.1.0.InsufficientPrivilege",
                "Message": (
                    f"The authenticated user lacks the required privileges to perform the {operation} "
                    f"operation{vm_context}."
                ),
            }
        ]
    elif status_code == 404:
        redfish_error_code = "Base.1.0.ResourceMissingAtURI"
        extended_info = [
            {"MessageId": "Base.1.0.ResourceMissingAtURI", "Message": f"The resource{vm_context} was not found."}
        ]
    elif status_code == 400:
        redfish_error_code = "Base.1.0.InvalidRequest"
        extended_info = [
            {"MessageId": "Base.1.0.InvalidRequest", "Message": f"The {operation} request was malformed or invalid."}
        ]
    else:
        # Fallback for other Proxmox errors (e.g., 500, 503)
        redfish_error_code = "Base.1.0.GeneralError"
        extended_info = [
            {"MessageId": "Base.1.0.GeneralError", "Message": f"An error occurred during {operation}{vm_context}."}
        ]

    return {
        "error": {
            "code": redfish_error_code,
            "message": f"{operation} failed: {message}",
            "@Message.ExtendedInfo": extended_info,
        }
    }, status_code


def get_proxmox_api(headers: Any) -> ProxmoxAPI:
    valid, message = validate_token(headers)
    if not valid:
        raise Exception(f"Authentication failed: {message}")

    # Always use the root session for Proxmox operations
    # The user authentication is handled in validate_token
    last_error = None
    for host in [entry.strip() for entry in PROXMOX_HOST.split(",") if entry.strip()]:
        try:
            proxmox = ProxmoxAPI(
                host,
                user=PROXMOX_USER,
                password=PROXMOX_PASSWORD,
                verify_ssl=VERIFY_SSL,
                timeout=1800,  # 30 minutes timeout for large uploads
            )
            proxmox.version.get()
            return proxmox
        except Exception as e:
            last_error = e
            logger.warning("Failed to connect to Proxmox API host %s: %s", host, str(e))

    if not PROXMOX_HOST.strip():
        raise Exception("Failed to connect to Proxmox API: PROXMOX_HOST is empty")

    raise Exception(f"Failed to connect to Proxmox API: {str(last_error)}")


def check_user_vm_permission(proxmox: ProxmoxAPI, username: str, vm_id: int) -> bool:
    """
    Check if a user has permission to access a specific VM.
    Uses the root session to check user permissions.

    Args:
        proxmox: ProxmoxAPI instance (root session)
        username: Username to check permissions for
        vm_id: VM ID to check access to

    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        # Get access control list to check user permissions
        acl = proxmox.access.get()
        logger.debug(f"Checking permissions for user {username} on VM {vm_id}")
        if acl is None:
            logger.warning("No ACL data returned from Proxmox API")
            return False
        logger.debug(f"Found {len(acl)} ACL entries")

        # Check if user has any permissions that would allow VM access
        for entry in acl:
            entry_ugid = entry.get("ugid", "")
            entry_path = entry.get("path", "")
            logger.debug(f"ACL entry: ugid={entry_ugid}, path={entry_path}")

            if entry_ugid == username:
                # Check if the user has permissions for this VM
                if entry_path == f"/vms/{vm_id}" or entry_path.startswith(f"/vms/{vm_id}/"):
                    # User has direct permissions for this VM
                    logger.info(f"User {username} has direct permissions for VM {vm_id}")
                    return True
                elif entry_path == "/vms" or entry_path == "/":
                    # User has permissions for all VMs
                    logger.info(f"User {username} has global VM permissions")
                    return True
                elif entry_path.startswith("/nodes/") and f"/qemu/{vm_id}" in entry_path:
                    # User has node-level permissions for this VM
                    logger.info(f"User {username} has node-level permissions for VM {vm_id}")
                    return True

        # Also check if user is in any groups that have permissions
        if acl is not None:
            for entry in acl:
                entry_ugid = entry.get("ugid", "")
                if entry_ugid.startswith("@") and entry_ugid != username:
                    # This is a group entry, check if user is in this group
                    group_name = entry_ugid[1:]  # Remove @ prefix
                    try:
                        # Check if user is in this group
                        group_members = proxmox.access.groups(group_name).get()
                        if group_members is not None:
                            for member in group_members:
                                if member.get("userid") == username.split("!")[0]:  # Remove token part
                                    # User is in this group, check if group has VM permissions
                                    path = entry.get("path", "")
                                    if path == f"/vms/{vm_id}" or path.startswith(f"/vms/{vm_id}/"):
                                        logger.info(f"User {username} has group permissions for VM {vm_id}")
                                        return True
                                    elif path == "/vms" or path == "/":
                                        logger.info(f"User {username} has global group permissions")
                                        return True
                    except Exception:
                        # Group doesn't exist or other error, continue
                        pass

        logger.warning(f"User {username} does not have permissions for VM {vm_id}")
        return False

    except Exception as e:
        logger.warning(f"Failed to check permissions for user {username} on VM {vm_id}: {str(e)}")
        # In case of error, deny access for security
        return False


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user by calling the Proxmox /access/ticket endpoint.
    This is the same logic used in the original redfish-proxmox.py script.

    Args:
        username: Username to authenticate (e.g., 'bmcadmin@pve')
        password: Password or token for the user

    Returns:
        bool: True if authentication successful, False otherwise
    """
    try:
        hosts = [entry.strip() for entry in PROXMOX_HOST.split(",") if entry.strip()]
        if not hosts:
            logger.warning("Authentication failed: PROXMOX_HOST is empty")
            return False

        # Check if this looks like an API token (contains '!' and is a UUID-like string)
        if "!" in username and len(password) == 36 and password.count("-") == 4:
            # This is an API token - use Authorization header format
            token_header = f"PVEAPIToken={username}={password}"
            for host in hosts:
                url = f"https://{host}:{PROXMOX_API_PORT}/api2/json/version"
                response = requests.get(url, headers={"Authorization": token_header}, verify=VERIFY_SSL, timeout=10)
                if response.status_code == 200:
                    logger.info(f"API token authentication successful for {username} via {host}")
                    return True
                logger.warning(f"API token authentication failed for {username} via {host}: HTTP {response.status_code}")
            return False
        else:
            # This is a regular username/password - use the ticket endpoint
            payload = {"username": username, "password": password}
            for host in hosts:
                url = f"https://{host}:{PROXMOX_API_PORT}/api2/json/access/ticket"
                response = requests.post(url, data=payload, verify=VERIFY_SSL, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "ticket" in data["data"]:
                        logger.info(f"User {username} authenticated successfully via {host}")
                        return True
                    logger.warning(f"User {username} authentication failed via {host}: no ticket in response")
                else:
                    logger.warning(f"User {username} authentication failed via {host}: HTTP {response.status_code}")
            return False

    except Exception as e:
        logger.warning(f"User {username} authentication failed with exception: {str(e)}")
        return False


def _purge_expired_sessions() -> None:
    """Remove expired sessions. Rate-limited to run at most once per minute."""
    global _last_session_purge
    now = time.time()
    if now - _last_session_purge < 60:
        return
    _last_session_purge = now
    expired = [t for t, s in sessions.items() if now - s.get("created", 0) >= SESSION_TTL_SECONDS]
    for t in expired:
        del sessions[t]


def _list_cluster_vm_resources(proxmox: ProxmoxAPI) -> list[Dict[str, Any]]:
    """List cluster-wide VM resources and keep only QEMU entries."""
    try:
        resources = proxmox.cluster.resources.get(type="vm")
    except ResourceException as e:
        if e.status_code in (400, 422):
            # Older Proxmox versions may not support the type filter parameter
            resources = proxmox.cluster.resources.get()
        else:
            raise
    if not isinstance(resources, list):
        return []
    return [resource for resource in resources if resource.get("type") == "qemu"]


def _get_vm_node(proxmox: ProxmoxAPI, vm_id: Union[str, int]) -> str:
    """Resolve the current node for a VM from cluster resources."""
    vmid = int(vm_id)
    for resource in _list_cluster_vm_resources(proxmox):
        if resource.get("vmid") == vmid:
            node_name = resource.get("node")
            if node_name:
                return str(node_name)

    if PROXMOX_NODE:
        logger.warning("Falling back to PROXMOX_NODE=%s for VM %s", PROXMOX_NODE, vmid)
        return PROXMOX_NODE

    raise ValueError(f"Unable to determine Proxmox node for VM {vmid}")


def _get_vm_resource(proxmox: ProxmoxAPI, vm_id: Union[str, int]) -> Any:
    """Return the proxmoxer resource for a VM on its current node."""
    return proxmox.nodes(_get_vm_node(proxmox, vm_id)).qemu(vm_id)


def _get_storage_node(proxmox: ProxmoxAPI, node_name: Optional[str] = None) -> str:
    """Return the node to use for storage operations."""
    if node_name:
        return node_name
    if PROXMOX_NODE:
        return PROXMOX_NODE
    return _get_default_node(proxmox)


def _get_default_node(proxmox: ProxmoxAPI) -> str:
    """Resolve a default cluster node when no VM-specific node is available."""
    try:
        nodes = proxmox.nodes.get()
        if isinstance(nodes, list):
            for node in nodes:
                node_name = node.get("node")
                if node_name:
                    return str(node_name)
    except Exception:
        pass

    for resource in _list_cluster_vm_resources(proxmox):
        node_name = resource.get("node")
        if node_name:
            return str(node_name)

    raise ValueError("PROXMOX_NODE is required only as a fallback when no VM node is available")


# _get_storage_node is defined above; iso.py can now import it safely
from proxmox_redfish.iso import (  # noqa: E402
    _ensure_iso_available,
    _find_iso_entry,
    _get_storage_details,
    _list_iso_storage_content,
    _storage_supports_iso,
    _upload_iso_file,
    _wait_for_task_completion,
    _download_iso_to_file,
    get_file_lock,
)


# Power control functions
def power_on(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    logger.info("Power On request for VM %s", vm_id)
    try:
        task = _get_vm_resource(proxmox, vm_id).status.start.post()
        logger.info("Power On initiated for VM %s, task: %s", vm_id, task)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power On VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power On request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        logger.error("Power On failed for VM %s: %s", vm_id, str(e), exc_info=True)
        return handle_proxmox_error("Power On", e, vm_id)


def power_off(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).status.shutdown.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power Off VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power Off request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Power Off", e, vm_id)


def reboot(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).status.reboot.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Reboot VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Reboot request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Reboot", e, vm_id)


def reset_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Perform a hard reset of the Proxmox VM, equivalent to a power cycle.

    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID

    Returns:
        Tuple of (response_dict, status_code) for Redfish response
    """
    try:
        task = _get_vm_resource(proxmox, vm_id).status.reset.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard Reset VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard reset request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard Reset", e, vm_id)


def suspend_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).status.suspend.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Pause VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Pause request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Pause", e, vm_id)


def resume_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).status.resume.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Resume VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Resume request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Resume", e, vm_id)


def stop_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).status.stop.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard stop VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard stop request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard stop", e, vm_id)


# Manage VirtualMedia state
def manage_virtual_media(
    proxmox: ProxmoxAPI, vm_id: int, action: str, iso_path: Optional[str] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Manage virtual media for a Proxmox VM, mapped to Redfish VirtualMedia actions.

    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID
        action: "InsertMedia" or "EjectMedia"
        iso_path: Path to ISO (for InsertMedia)

    Returns:
        Tuple of (response_dict, status_code)
    """
    logger.info("VirtualMedia operation: action=%s, vm_id=%s, iso_path=%s", action, vm_id, iso_path)

    try:
        vm_resource = _get_vm_resource(proxmox, vm_id)
        vm_node = _get_vm_node(proxmox, vm_id)
        vm_config = vm_resource.config

        if action == "InsertMedia":
            if not iso_path:
                logger.error("InsertMedia failed: No ISO path provided for VM %s", vm_id)
                return {
                    "error": {"code": "Base.1.0.InvalidRequest", "message": "ISO path is required for InsertMedia"}
                }, 400

            logger.info("Processing InsertMedia for VM %s with ISO: %s", vm_id, iso_path)
            iso_path = _ensure_iso_available(proxmox, iso_path, vm_node)
            logger.info("ISO prepared for VM %s: %s", vm_id, iso_path)

            config_data = {"ide2": f"{iso_path},media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.debug("Setting boot order for VM %s to ide2", vm_id)
            vm_config.post(boot="order=ide2")

            logger.info("InsertMedia completed successfully for VM %s, task: %s", vm_id, task)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Insert Media for VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Mounted ISO {iso_path} to VM {vm_id}"}],
            }, 202

        elif action == "EjectMedia":
            logger.info("Processing EjectMedia for VM %s", vm_id)
            config_data = {"ide2": "none,media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.info("EjectMedia completed successfully for VM %s, task: %s", vm_id, task)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Eject Media from VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Ejected ISO from VM {vm_id}"}],
            }, 202
        else:
            logger.error("Unsupported VirtualMedia action: %s for VM %s", action, vm_id)
            return {"error": {"code": "Base.1.0.InvalidRequest", "message": f"Unsupported action: {action}"}}, 400

    except Exception as e:
        logger.error("VirtualMedia %s failed for VM %s: %s", action, vm_id, str(e), exc_info=True)
        return handle_proxmox_error(f"Virtual Media {action}", e, vm_id)


# Update VM config (unchanged)
def update_vm_config(proxmox: ProxmoxAPI, vm_id: int, config_data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    try:
        task = _get_vm_resource(proxmox, vm_id).config.post(**config_data)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Update Configuration for VM {vm_id}",
            "TaskState": "Running",  # Initial state; client can poll for updates
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Configuration update initiated for VM {vm_id}"}],
        }, 202  # 202 Accepted indicates an asynchronous task
    except Exception as e:
        return handle_proxmox_error("Update Configuration", e, vm_id)


def reorder_boot_order(proxmox: ProxmoxAPI, vm_id: int, current_order: str, target: str) -> str:
    """
    Reorder Proxmox boot devices based on Redfish target, preserving all devices including multiple hard drives.
    Returns the new boot order string for Proxmox config.
    """
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            raise ValueError("Failed to retrieve VM configuration")

        # Parse current boot order
        devices = current_order.split(";") if current_order else []
        # Initialize device lists
        disk_devs = []
        cd_dev = None
        net_dev = None

        # Check for hard drives and CD-ROMs across all device types.
        # VirtIO devices are block-only (no media=cdrom support).
        for dev_type, dev_count in DISK_DEVICE_RANGES:
            for i in range(dev_count):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    dev_value = config[dev_key]
                    if dev_type != "virtio" and "media=cdrom" in dev_value:
                        cd_dev = dev_key
                    else:
                        disk_devs.append(dev_key)  # Hard drive found

        for i in range(NET_DEVICE_COUNT):
            net_key = f"net{i}"
            if net_key in config:
                net_dev = net_key
                break

        # Build the full list of available devices, preserving all from config and current order
        available_devs = [d for d in devices if d in config] if devices else []
        for dev in disk_devs + ([cd_dev] if cd_dev else []) + ([net_dev] if net_dev else []):
            if dev and dev not in available_devs:
                available_devs.append(dev)

        # Validate the target device availability
        if target == "Pxe" and not net_dev:
            raise ValueError("No network device available for Pxe boot")
        elif target == "Cd" and not cd_dev:
            raise ValueError("No CD-ROM device available for Cd boot")
        elif target == "Hdd" and not disk_devs:
            raise ValueError("No hard disk device available for Hdd boot")

        # Reorder based on target, keeping all devices
        new_order = []
        if target == "Pxe" and net_dev:
            new_order = [net_dev] + [d for d in available_devs if d != net_dev]
        elif target == "Cd" and cd_dev:
            new_order = [cd_dev] + [d for d in available_devs if d != cd_dev]
        elif target == "Hdd" and disk_devs:
            primary_disk = disk_devs[0]
            new_order = [primary_disk] + [d for d in available_devs if d != primary_disk]
        else:
            # This should not be reached due to earlier validation
            new_order = available_devs

        # Remove duplicates and ensure valid devices only
        unique_devices = list(dict.fromkeys(new_order))
        result = ";".join(unique_devices) if unique_devices else ""
        logger.debug(f"Computed new boot order for VM {vm_id}: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to reorder boot order for VM {vm_id}: {str(e)}")
        raise


def get_bios(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error("BIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        firmware_type = config.get("bios", "seabios")
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Minimal BIOS info with link to SMBIOS details
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "Bios",
            "Name": "BIOS Settings",
            "FirmwareMode": firmware_mode,  # From previous enhancement
            "Attributes": {"BootOrder": config.get("boot", "order=scsi0;ide2;net0")},
            "Links": {"SMBIOS": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS"}},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("BIOS retrieval", e, vm_id)


def get_smbios_type1(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Retrieve SMBIOS Type 1 (System Information) data from Proxmox VM config,
    including firmware type (BIOS or UEFI).
    """
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error("SMBIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        smbios1 = config.get("smbios1", "")
        firmware_type = config.get("bios", "seabios")  # Default to seabios if not specified

        # Map Proxmox bios setting to Redfish-friendly terms
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Default SMBIOS values
        smbios_data = {
            "UUID": None,
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": None,
            "SKUNumber": None,
            "Family": None,
        }

        # Parse smbios1 string if it exists
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)

                    # Attempt to decode Base64 if it looks encoded
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        # Only use decoded value if it's valid UTF-8 and not a UUID
                        if key != "uuid" and decoded_value.isprintable():
                            value = decoded_value
                    except (binascii.Error, UnicodeDecodeError):
                        pass  # Keep original value if decoding fails

                    if key == "uuid":
                        smbios_data["UUID"] = value
                    elif key == "manufacturer":
                        smbios_data["Manufacturer"] = value
                    elif key == "product":
                        smbios_data["ProductName"] = value
                    elif key == "version":
                        smbios_data["Version"] = value
                    elif key == "serial":
                        smbios_data["SerialNumber"] = value
                    elif key == "sku":
                        smbios_data["SKUNumber"] = value
                    elif key == "family":
                        smbios_data["Family"] = value

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "SMBIOS",
            "Name": "SMBIOS System Information",
            "FirmwareMode": firmware_mode,  # New field to indicate BIOS or UEFI
            "Attributes": {"SMBIOSType1": smbios_data},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("SMBIOS retrieval", e, vm_id)


def get_vm_config(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Optional helper function for config details (not a standard Redfish endpoint).
    Returns a subset of data for custom use, but prefer get_vm_status for Redfish compliance.
    """
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Configuration retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        return {
            "Name": config.get("name", f"VM-{vm_id}"),
            "MemoryMB": config.get("memory", 0),
            "CPUCores": config.get("cores", 0),
            "Sockets": config.get("sockets", 1),
            "CDROM": config.get("ide2", "none"),
        }
    except Exception as e:
        return handle_proxmox_error("Configuration retrieval", e, vm_id)


def validate_token(headers: Any) -> Tuple[bool, str]:
    if AUTH is None:
        return True, "No auth required"
    elif AUTH == "Basic":
        auth_header = headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                username, password = credentials.split(":", 1)
                if "@" not in username:
                    username += "@pam"
                if authenticate_user(username, password):
                    _purge_expired_sessions()
                    token = secrets.token_hex(16)
                    sessions[token] = {"created": time.time(), "username": username, "password": password}
                    return True, username
                else:
                    return False, f"Invalid Basic Authentication credentials for user {username}"
            except Exception as e:
                return False, f"Invalid Basic Authentication format: {str(e)}"
        else:
            return False, "Basic Authentication required but no valid Authorization header provided"
    elif AUTH == "Session":
        token = headers.get("X-Auth-Token")
        if token in sessions:
            session = sessions[token]
            if time.time() - session["created"] < SESSION_TTL_SECONDS:
                return True, session["username"]
            else:
                del sessions[token]
                return False, "Token expired"
        else:
            return False, "Invalid or no token provided"
    else:
        return False, "Invalid authentication method"


def get_processor_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Processor collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        # Removed unused variables 'cores' and 'sockets'
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors",
            "@odata.type": "#ProcessorCollection.ProcessorCollection",
            "Name": "Processor Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/CPU1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor collection retrieval", e, vm_id)


def get_processor_detail(
    proxmox: ProxmoxAPI, vm_id: int, processor_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Processor detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        cores = config.get("cores", 1)
        sockets = config.get("sockets", 1)
        total_cores = cores * sockets

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/{processor_id}",
            "@odata.type": "#Processor.v1_0_0.Processor",
            "Id": processor_id,
            "Name": f"Processor {processor_id}",
            "TotalCores": total_cores,
            "TotalThreads": total_cores,  # Assuming 1 thread per core
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor detail retrieval", e, vm_id)


def get_storage_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage",
            "@odata.type": "#StorageCollection.StorageCollection",
            "Name": "Storage Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage collection retrieval", e, vm_id)


def parse_disk_size(drive_info: Dict[str, Any]) -> str:
    """
    Parse disk size from Proxmox config string (e.g., 'size=16G') and convert to bytes.
    Returns size as a string representation in bytes.
    """
    try:
        size_str = drive_info.get("size", "0")
        if not size_str or size_str == "0":
            return "0"
        # Handle size strings like "16G", "500M", etc.
        if isinstance(size_str, str):
            size_str = size_str.upper()
            if size_str.endswith("G"):
                size_gb = float(size_str[:-1])
                size_bytes = int(size_gb * 1024 * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("M"):
                size_mb = float(size_str[:-1])
                size_bytes = int(size_mb * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("K"):
                size_kb = float(size_str[:-1])
                size_bytes = int(size_kb * 1024)
                return str(size_bytes)
            else:
                # Assume it's already in bytes
                return str(int(float(size_str)))
        else:
            return str(int(float(size_str)))
    except (ValueError, TypeError):
        return "0"


def get_storage_detail(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Storage detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get disk drives from config
        drives = []
        for dev_type, dev_count in DISK_DEVICE_RANGES:
            for i in range(dev_count):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    drives.append({"Id": dev_key, "Name": f"Drive {dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}",
            "@odata.type": "#Storage.v1_0_0.Storage",
            "Id": storage_id,
            "Name": f"Storage {storage_id}",
            "Drives": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives"},
            "Volumes": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes"},
            "Controllers": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage detail retrieval", e, vm_id)


def get_drive_detail(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str, drive_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Drive detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        if drive_id not in config:
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Drive {drive_id} not found"}}, 404

        drive_config = config[drive_id]
        size = parse_disk_size({"size": drive_config})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives/{drive_id}",
            "@odata.type": "#Drive.v1_0_0.Drive",
            "Id": drive_id,
            "Name": f"Drive {drive_id}",
            "CapacityBytes": size,
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Drive detail retrieval", e, vm_id)


def get_volume_collection(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Volume collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get volumes from config
        volumes = []
        for dev_type, dev_count in DISK_DEVICE_RANGES:
            for i in range(dev_count):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    volumes.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes/{dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes",
            "@odata.type": "#VolumeCollection.VolumeCollection",
            "Name": "Volume Collection",
            "Members": volumes,
            "Members@odata.count": len(volumes),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Volume collection retrieval", e, vm_id)


def get_controller_collection(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Controller collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get controllers from config
        controllers = []
        for dev_type, dev_count in DISK_DEVICE_RANGES:
            for i in range(dev_count):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    controllers.append(
                        {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers/{dev_type}"}
                    )

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers",
            "@odata.type": "#ControllerCollection.ControllerCollection",
            "Name": "Controller Collection",
            "Members": controllers,
            "Members@odata.count": len(controllers),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Controller collection retrieval", e, vm_id)


def get_ethernet_interface_collection(
    proxmox: ProxmoxAPI, vm_id: int
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Ethernet interface collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        interfaces = []
        for i in range(NET_DEVICE_COUNT):
            net_key = f"net{i}"
            if net_key in config:
                interfaces.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{net_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces",
            "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
            "Name": "Ethernet Interface Collection",
            "Members": interfaces,
            "Members@odata.count": len(interfaces),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface collection retrieval", e, vm_id)


def get_ethernet_interface_detail(
    proxmox: ProxmoxAPI, vm_id: int, interface_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Ethernet interface detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        if interface_id not in config:
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Interface {interface_id} not found"}
            }, 404

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{interface_id}",
            "@odata.type": "#EthernetInterface.v1_0_0.EthernetInterface",
            "Id": interface_id,
            "Name": f"Interface {interface_id}",
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface detail retrieval", e, vm_id)


def get_virtual_media(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Get virtual media information for a Proxmox VM.
    """
    try:
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Virtual media retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Inserted is True only if ide2 is present, is a cdrom, and not 'none,media=cdrom'
        cd_configured = "ide2" in config and "media=cdrom" in config["ide2"] and not config["ide2"].startswith("none")

        response = {
            "@odata.id": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd",
            "@odata.type": "#VirtualMedia.v1_0_0.VirtualMedia",
            "Id": "Cd",
            "Name": "Virtual CD",
            "MediaTypes": ["CD", "DVD"],
            "ConnectedVia": "Applet",
            "Inserted": cd_configured,
            "WriteProtected": True,
            "Actions": {
                "#VirtualMedia.InsertMedia": {
                    "target": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"
                },
                "#VirtualMedia.EjectMedia": {
                    "target": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"
                },
            },
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Virtual media retrieval", e, vm_id)


def get_manager(proxmox: ProxmoxAPI, manager_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Get manager information for a Proxmox VM.
    """
    try:
        # Map manager_id to vm_id (they are the same in our implementation)
        vm_id = manager_id

        # Get VM config to verify it exists
        config = _get_vm_resource(proxmox, vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Manager retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        response = {
            "@odata.id": f"/redfish/v1/Managers/{manager_id}",
            "@odata.type": "#Manager.v1_0_0.Manager",
            "Id": str(manager_id),
            "Name": f"Manager for VM {vm_id}",
            "ManagerType": "BMC",
            "Status": {"State": "Enabled", "Health": "OK"},
            "VirtualMedia": {"@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Manager retrieval", e, manager_id)


def get_vm_status(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        vm_resource = _get_vm_resource(proxmox, vm_id)
        status = vm_resource.status.current.get()
        if status is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM status"), vm_id)

        config = vm_resource.config.get()
        if config is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Map Proxmox status to Redfish power state
        proxmox_status = status.get("status", "unknown")
        if proxmox_status == "running":
            power_state = "On"
            health = "OK"
        elif proxmox_status == "stopped":
            power_state = "Off"
            health = "OK"
        elif proxmox_status == "paused":
            power_state = "Paused"
            health = "Warning"
        else:
            power_state = "Unknown"
            health = "Critical"

        # Add Memory field as expected by tests
        memory_mb = config.get("memory", 0)
        try:
            memory_mb = float(memory_mb)
        except (ValueError, TypeError):
            memory_mb = 0
        memory_gib = memory_mb / 1024.0
        memory_field = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Memory",
            "TotalSystemMemoryGiB": round(memory_gib, 2),
        }

        # Add Boot field as expected by tests
        boot_order = config.get("boot", "")
        boot_field = {
            "BootSourceOverrideEnabled": "Once",  # or "Continuous"/"Disabled" as appropriate
            "BootSourceOverrideTarget": "None",  # Could be "Pxe", "Cd", "Hdd", etc.
            "BootSourceOverrideMode": "UEFI" if config.get("bios") == "ovmf" else "Legacy",
            "BootSourceOverrideTarget@Redfish.AllowableValues": ["Pxe", "Cd", "Hdd"],
            "BootSourceOverrideMode@Redfish.AllowableValues": ["UEFI", "Legacy"],
            "BootOrder": boot_order,
        }

        # Add Actions field as expected by tests
        actions_field = {
            "#ComputerSystem.Reset": {
                "target": f"/redfish/v1/Systems/{vm_id}/Actions/ComputerSystem.Reset",
                "ResetType@Redfish.AllowableValues": [
                    "On",
                    "ForceOff",
                    "GracefulShutdown",
                    "GracefulRestart",
                    "ForceRestart",
                    "Nmi",
                    "PowerCycle",
                ],
            }
        }

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}",
            "@odata.type": "#ComputerSystem.v1_0_0.ComputerSystem",
            "Id": str(vm_id),
            "Name": config.get("name", f"VM-{vm_id}"),
            "SystemType": "Physical",
            "Status": {"State": power_state, "Health": health},
            "PowerState": power_state,
            "Bios": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios"},
            "Processors": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors"},
            "Memory": memory_field,
            "Storage": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage"},
            "EthernetInterfaces": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces"},
            "Boot": boot_field,
            "Actions": actions_field,
            "Links": {"ManagedBy": [{"@odata.id": f"/redfish/v1/Managers/{vm_id}"}]},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("VM status retrieval", e, vm_id)


# When running as a script (__main__), register this module under its
# package-qualified name before loading handler.py.  All symbols handler.py
# needs are defined by this point, so the import resolves correctly without
# triggering a second full execution of this file.
if "proxmox_redfish.proxmox_redfish" not in sys.modules:
    sys.modules["proxmox_redfish.proxmox_redfish"] = sys.modules[__name__]

from proxmox_redfish.handler import RedfishRequestHandler  # noqa: E402


# Server function
def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    server_address = (host, port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on {host}:{port}...")
    httpd.serve_forever()


# Server function with configurable SSL certificates
def run_server_ssl(host: str = "0.0.0.0", port: int = 443) -> None:
    server_address = (host, port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Check if certificate files exist
    if not os.path.exists(SSL_CERT_FILE):
        raise FileNotFoundError(f"SSL certificate file not found: {SSL_CERT_FILE}")
    if not os.path.exists(SSL_KEY_FILE):
        raise FileNotFoundError(f"SSL key file not found: {SSL_KEY_FILE}")

    # Load certificate chain
    if os.path.exists(SSL_CA_FILE):
        # Load certificate with CA bundle
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        context.load_verify_locations(cafile=SSL_CA_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}, CA: {SSL_CA_FILE}")
    else:
        # Load certificate without CA bundle
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}")

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Redfish server running on {host}:{port} with SSL...")
    logger.info(f"Redfish server started on {host}:{port} with SSL certificates")
    httpd.serve_forever()


def main() -> None:
    """Main entry point for the proxmox-redfish daemon."""
    parser = argparse.ArgumentParser(description="Proxmox Redfish Daemon - Redfish API for Proxmox VMs")
    parser.add_argument("--config", help="Path to configuration file (JSON format)")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--port", type=int, help="Port to run the server on (overrides config)")
    parser.add_argument("--host", help="Host to bind to (default: 0.0.0.0)")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    # Load configuration
    config = {}

    # Load from config file if specified
    if args.config:
        try:
            with open(args.config, "r") as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config file {args.config}: {e}")
            sys.exit(1)

    # Override with environment variables
    if os.getenv("PROXMOX_HOST"):
        config.setdefault("proxmox", {})["host"] = os.getenv("PROXMOX_HOST")
    if os.getenv("PROXMOX_USER"):
        config.setdefault("proxmox", {})["user"] = os.getenv("PROXMOX_USER")
    if os.getenv("PROXMOX_PASSWORD"):
        config.setdefault("proxmox", {})["password"] = os.getenv("PROXMOX_PASSWORD")
    port_value = os.getenv("REDFISH_PORT")
    if port_value:
        config.setdefault("redfish", {})["port"] = int(port_value)
    host_value = os.getenv("REDFISH_HOST")
    if host_value:
        config.setdefault("redfish", {})["host"] = host_value
    if os.getenv("SSL_CERT_FILE"):
        config.setdefault("redfish", {})["ssl_cert"] = os.getenv("SSL_CERT_FILE")
    if os.getenv("SSL_KEY_FILE"):
        config.setdefault("redfish", {})["ssl_key"] = os.getenv("SSL_KEY_FILE")
    if os.getenv("LOG_LEVEL"):
        config.setdefault("logging", {})["level"] = os.getenv("LOG_LEVEL")

    # Override with command line arguments
    if args.port:
        config.setdefault("redfish", {})["port"] = args.port
    if args.host:
        config.setdefault("redfish", {})["host"] = args.host

    # Set defaults
    config.setdefault("redfish", {}).setdefault("port", 8443)
    config.setdefault("redfish", {}).setdefault("host", "0.0.0.0")
    config.setdefault("logging", {}).setdefault("level", "INFO")

    # Validate required configuration
    proxmox_config = config.get("proxmox", {})
    if not all(key in proxmox_config for key in ["host", "user", "password"]):
        logger.error("Missing required Proxmox configuration: host, user, password")
        logger.error("Set via environment variables or config file")
        sys.exit(1)

    # Start the daemon
    try:
        logger.info("Starting Proxmox Redfish Daemon...")
        logger.info(f"Proxmox Host: {proxmox_config['host']}")
        logger.info(f"Redfish Bind Host: {config['redfish']['host']}")
        logger.info(f"Redfish Port: {config['redfish']['port']}")

        # Check if SSL certificates are configured
        ssl_cert = config.get("redfish", {}).get("ssl_cert")
        ssl_key = config.get("redfish", {}).get("ssl_key")

        if ssl_cert and ssl_key:
            # Start SSL server
            logger.info("Starting Redfish server with SSL...")
            run_server_ssl(config["redfish"]["host"], config["redfish"]["port"])
        else:
            # Start regular HTTP server
            logger.info("Starting Redfish server without SSL...")
            run_server(config["redfish"]["host"], config["redfish"]["port"])

    except KeyboardInterrupt:
        logger.info("Shutting down Proxmox Redfish Daemon...")

    except Exception as e:
        logger.error(f"Failed to start daemon: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

__all__ = [
    "RedfishRequestHandler",
    "power_on",
    "power_off",
    "reboot",
    "reset_vm",
    "manage_virtual_media",
    "get_vm_status",
    "get_bios",
    "validate_token",
    "get_proxmox_api",
    "handle_proxmox_error",
    "reorder_boot_order",
    "_ensure_iso_available",
    "ProxmoxAPI",
    "sessions",
    "AUTH",
    "SECURE",
    "PROXMOX_HOST",
    "PROXMOX_USER",
    "PROXMOX_PASSWORD",
    "PROXMOX_NODE",
    "VERIFY_SSL",
]
