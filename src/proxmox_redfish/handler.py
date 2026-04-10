#!/usr/bin/env python3
"""Redfish HTTP request handler — routes GET/POST/PATCH to business logic."""

import base64
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Tuple, Union

from proxmoxer import ProxmoxAPI
import proxmox_redfish.proxmox_redfish as _app


class RedfishRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        # Log request details
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        _app.logger.debug(f"GET Request: path={self.path}, headers=\n{headers_str}")

        path = self.path.rstrip("/")
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        # Allow root endpoint without authentication for service discovery
        if path == "/redfish/v1":
            response = {
                "@odata.id": "/redfish/v1",
                "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
                "Id": "RootService",
                "Name": "Redfish Root Service",
                "RedfishVersion": "1.0.0",
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
            }
        else:
            # Require authentication for all other endpoints
            valid, message = _app.validate_token(self.headers)
            if not valid:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
            else:
                proxmox = _app.get_proxmox_api(self.headers)
                parts = path.split("/")
                if path == "/redfish/v1/Systems":
                    try:
                        vm_list = _app._list_cluster_vm_resources(proxmox)
                        members = [{"@odata.id": f"/redfish/v1/Systems/{vm['vmid']}"} for vm in vm_list]
                        response = {
                            "@odata.id": "/redfish/v1/Systems",
                            "@odata.type": "#SystemCollection.SystemCollection",
                            "Name": "Systems Collection",
                            "Members": members,
                            "Members@odata.count": len(members),
                        }
                    except Exception as e:
                        status_code = 500
                        response = {
                            "error": {
                                "code": "Base.1.0.GeneralError",
                                "message": f"Failed to retrieve VM list: {str(e)}",
                            }
                        }
                elif path.startswith("/redfish/v1/Systems/"):
                    if len(parts) == 5 and parts[4].isdigit():  # /redfish/v1/Systems/<vm_id>
                        vm_id = int(parts[4])
                        response = _app.get_vm_status(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    # START NEW CODE: Handle /redfish/v1/Systems/<vm_id>/Bios
                    elif len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                        vm_id = int(parts[4])
                        response = _app.get_bios(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    # END NEW CODE
                    elif len(parts) == 6 and parts[5] == "Processors":  # /redfish/v1/Systems/<vm_id>/Processors
                        vm_id = int(parts[4])
                        response = _app.get_processor_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "Processors"
                    ):  # /redfish/v1/Systems/<vm_id>/Processors/<processor_id>
                        vm_id = int(parts[4])
                        processor_id = parts[6]
                        response = _app.get_processor_detail(proxmox, vm_id, processor_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif len(parts) == 6 and parts[5] == "Storage":  # /redfish/v1/Systems/<vm_id>/Storage
                        vm_id = int(parts[4])
                        response = _app.get_storage_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "Storage" and parts[6].isdigit()
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = _app.get_storage_detail(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 9 and parts[5] == "Storage" and parts[7] == "Drives"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Drives/<drive_id>
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        drive_id = parts[8]
                        response = _app.get_drive_detail(proxmox, vm_id, storage_id, drive_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Volumes"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Volumes
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = _app.get_volume_collection(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Controllers"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Controllers
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = _app.get_controller_collection(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 6 and parts[5] == "EthernetInterfaces"
                    ):  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces
                        vm_id = int(parts[4])
                        response = _app.get_ethernet_interface_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "EthernetInterfaces"
                    ):  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces/<interface_id>
                        vm_id = int(parts[4])
                        interface_id = parts[6]
                        response = _app.get_ethernet_interface_detail(proxmox, vm_id, interface_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    else:
                        status_code = 404
                        response = {
                            "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}
                        }
                # --- New: Managers endpoints (Metal3/Ironic path) -----------------
                elif path.startswith("/redfish/v1/Managers/") and len(parts) == 5 and parts[4].isdigit():
                    # /redfish/v1/Managers/<manager_id> - Manager detail
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = _app.get_manager(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif path.startswith("/redfish/v1/Managers/") and len(parts) == 6 and parts[5] == "VirtualMedia":
                    # /redfish/v1/Managers/1/VirtualMedia - VirtualMedia collection
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = {
                        "@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia",
                        "@odata.type": "#VirtualMediaCollection.VirtualMediaCollection",
                        "Name": "Virtual Media Collection",
                        "Members": [{"@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia/Cd"}],
                        "Members@odata.count": 1,
                    }
                elif (
                    path.startswith("/redfish/v1/Managers/")
                    and len(parts) == 7
                    and parts[5] == "VirtualMedia"
                    and parts[6] == "Cd"
                ):
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = _app.get_virtual_media(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                else:
                    status_code = 404
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}

        response_body = json.dumps(response).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)
        _app.logger.debug(f"GET Response: path={self.path}, status={status_code}, body={json.dumps(response)}")

    def do_POST(self) -> None:
        # Log request details
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            post_data_str = post_data.decode("utf-8")
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        _app.logger.debug(
            f"POST Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}"
        )

        path = self.path
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        token = None
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        if path == "/redfish/v1/SessionService/Sessions" and _app.AUTH == "Session":
            try:
                data = json.loads(post_data.decode("utf-8"))
                username = data.get("UserName")
                password = data.get("Password")
                if not username or not password:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Missing credentials"}}
                else:
                    if "@" not in username:
                        username += "@pam"
                    hosts = [entry.strip() for entry in _app.PROXMOX_HOST.split(",") if entry.strip()]
                    proxmox = None
                    for host in hosts:
                        try:
                            proxmox = ProxmoxAPI(host, user=username, password=password, verify_ssl=_app.VERIFY_SSL)
                            proxmox.version.get()
                            break
                        except Exception:
                            proxmox = None
                    if proxmox is None:
                        raise Exception("Failed to establish a Proxmox session on any configured host")
                    token = secrets.token_hex(16)
                    _app.sessions[token] = {"username": username, "password": password, "created": time.time()}
                    status_code = 201
                    response = {
                        "@odata.id": f"/redfish/v1/SessionService/Sessions/{token}",
                        "Id": token,
                        "UserName": username,
                    }
            except Exception as e:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Authentication failed: {str(e)}"}}
        else:
            valid, message = _app.validate_token(self.headers)
            if not valid:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
            else:
                # Get the authenticated username
                auth_header = self.headers.get("Authorization")
                if auth_header and auth_header.startswith("Basic "):
                    credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                    username, password = credentials.split(":", 1)
                    if "@" not in username:
                        username += "@pam"
                else:
                    # For session auth, get username from token
                    token = self.headers.get("X-Auth-Token")
                    if token in _app.sessions:
                        username = _app.sessions[token]["username"]
                    else:
                        username = "unknown"

                proxmox = _app.get_proxmox_api(self.headers)

                # Handle payload parsing based on endpoint
                if post_data:
                    try:
                        data = json.loads(post_data.decode("utf-8"))
                    except json.JSONDecodeError:
                        status_code = 400
                        response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                        response_body = json.dumps(response).encode("utf-8")
                        self.send_response(status_code)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(response_body)
                        # Log response
                        _app.logger.debug(
                            f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}"
                        )
                        return

                    data = json.loads(post_data.decode("utf-8"))
                    if path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.Reset" in path:
                        vm_id = int(path.split("/")[4])

                        # Check user permissions for this VM
                        _app.logger.info(f"Temporarily bypassing permission check for user {username} on VM {vm_id}")
                        # if not check_user_vm_permission(proxmox, username, vm_id):
                        #     status_code = 403
                        #     response = {
                        #         "error": {
                        #             "code": "Base.1.0.InsufficientPrivilege",
                        #             "message": f"User {username} does not have permission to access VM {vm_id}"
                        #         }
                        #     }
                        # else:
                        reset_type = data.get("ResetType", "")
                        if reset_type == "On":
                            response, status_code = _app.power_on(proxmox, vm_id)
                        elif reset_type == "GracefulShutdown":
                            response, status_code = _app.power_off(proxmox, vm_id)
                        elif reset_type == "ForceOff":
                            response, status_code = _app.stop_vm(proxmox, vm_id)
                        elif reset_type == "GracefulRestart":
                            response, status_code = _app.reboot(proxmox, vm_id)
                        elif reset_type == "ForceRestart":
                            response, status_code = _app.reset_vm(proxmox, vm_id)
                        elif reset_type == "Pause":
                            response, status_code = _app.suspend_vm(proxmox, vm_id)
                        elif reset_type == "Resume":
                            response, status_code = _app.resume_vm(proxmox, vm_id)
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.InvalidRequest",
                                    "message": f"Unsupported ResetType: {reset_type}",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.PropertyValueNotInList",
                                            "Message": f"The value '{reset_type}' for ResetType is not in the supported list: On, GracefulShutdown, ForceOff, GracefulRestart, ForceRestart, Pause, Resume.",
                                            "MessageArgs": [reset_type],
                                            "Severity": "Warning",
                                            "Resolution": "Select a supported ResetType value.",
                                        }
                                    ],
                                }
                            }
                    elif (
                        path.startswith("/redfish/v1/Systems/")
                        and "/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia" in path
                    ):
                        vm_id = int(path.split("/")[4])
                        iso_path = data.get("Image")
                        response, status_code = _app.manage_virtual_media(proxmox, vm_id, "InsertMedia", iso_path)
                    elif (
                        path.startswith("/redfish/v1/Systems/")
                        and "/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        vm_id = int(path.split("/")[4])
                        response, status_code = _app.manage_virtual_media(proxmox, vm_id, "EjectMedia")
                    # --- New: Managers/…/VirtualMedia (sushy default path) -----------------
                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia" in path
                    ):
                        manager_id = path.split("/")[4]  # usually "1"
                        iso_path = data.get("Image")
                        # map Manager-ID → VM-ID  (here we treat them as identical)
                        vm_id = int(manager_id)
                        response, status_code = _app.manage_virtual_media(proxmox, vm_id, "InsertMedia", iso_path)

                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        manager_id = path.split("/")[4]
                        vm_id = int(manager_id)
                        response, status_code = _app.manage_virtual_media(proxmox, vm_id, "EjectMedia")
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.UpdateConfig" in path:
                        vm_id = int(path.split("/")[4])
                        config_data = data
                        response, status_code = _app.update_vm_config(proxmox, vm_id, config_data)
                    else:
                        status_code = 404
                        response = {
                            "error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}
                        }

        # Convert response to JSON and calculate its length
        response_body = json.dumps(response).encode("utf-8")
        content_length = len(response_body)

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        if token and path == "/redfish/v1/SessionService/Sessions":
            self.send_header("X-Auth-Token", token)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

        # Log response
        _app.logger.debug(f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}")

    def do_PATCH(self) -> None:
        # Log request details
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            post_data_str = post_data.decode("utf-8")
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        _app.logger.debug(
            f"PATCH Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}"
        )

        path = self.path.rstrip("/")
        parts = path.split("/")
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        _app.logger.debug(f"Processing PATCH request for path: {path}")

        valid, message = _app.validate_token(self.headers)
        if not valid:
            _app.logger.error(f"Authentication failed: {message}")
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            try:
                proxmox = _app.get_proxmox_api(self.headers)
                _app.logger.debug("Proxmox API connection established for VM operation")
            except Exception as e:
                _app.logger.error(f"Failed to get Proxmox API: {str(e)}")
                status_code = 500
                response = {
                    "error": {"code": "Base.1.0.GeneralError", "message": f"Failed to connect to Proxmox API: {str(e)}"}
                }
                response_body = json.dumps(response).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)
                _app.logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
                return

            if len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                vm_id = parts[4]
                try:
                    data = json.loads(post_data.decode("utf-8"))
                    if "Attributes" in data:
                        attributes = data["Attributes"]
                        if "FirmwareMode" in attributes:
                            mode = attributes["FirmwareMode"]
                            if mode not in ["BIOS", "UEFI"]:
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.PropertyValueNotInList",
                                        "message": f"Invalid FirmwareMode: {mode}",
                                    }
                                }
                            else:
                                bios_setting = "seabios" if mode == "BIOS" else "ovmf"
                                task = _app._get_vm_resource(proxmox, vm_id).config.set(bios=bios_setting)
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set BIOS Mode for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [{"Message": f"Set BIOS mode to {mode} for VM {vm_id}"}],
                                }
                                status_code = 202
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyUnknown",
                                    "message": "No supported attributes provided",
                                }
                            }
                    else:
                        status_code = 400
                        response = {
                            "error": {
                                "code": "Base.1.0.InvalidRequest",
                                "message": "Attributes object required in PATCH request",
                            }
                        }
                except json.JSONDecodeError:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                except Exception as e:
                    response, status_code = _app.handle_proxmox_error("BIOS update", e, vm_id)
            elif path.startswith("/redfish/v1/Systems/") and len(parts) == 5:
                vm_id = path.split("/")[4]
                _app.logger.debug(f"Processing boot configuration for VM {vm_id}")
                try:
                    data = json.loads(post_data.decode("utf-8"))
                    _app.logger.debug(f"Parsed payload: {json.dumps(data, indent=2)}")
                    # START NEW CODE: Handle sushy ironic drive's incorrect BootSourceOverrideMode request
                    if "Boot" in data and "BootSourceOverrideMode" in data["Boot"]:
                        _app.logger.warning(
                            f"Received non-standard BootSourceOverrideMode request at /redfish/v1/Systems/{vm_id}; redirecting to BIOS handling"
                        )
                        mode = data["Boot"]["BootSourceOverrideMode"]
                        # Map BootSourceOverrideMode to FirmwareMode
                        mode_map = {"UEFI": "UEFI", "Legacy": "BIOS"}
                        if mode not in mode_map:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyValueNotInList",
                                    "message": f"Invalid BootSourceOverrideMode: {mode}",
                                }
                            }
                        else:
                            firmware_mode = mode_map[mode]
                            bios_setting = "seabios" if firmware_mode == "BIOS" else "ovmf"
                            task = _app._get_vm_resource(proxmox, vm_id).config.set(bios=bios_setting)
                            response = {
                                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                "@odata.type": "#Task.v1_0_0.Task",
                                "Id": task,
                                "Name": f"Set BIOS Mode for VM {vm_id}",
                                "TaskState": "Completed",  # Changed from "Running" to indicate immediate completion
                                "TaskStatus": "OK",
                                "Messages": [{"Message": f"Set BIOS mode to {firmware_mode} for VM {vm_id}"}],
                            }
                            status_code = 200  # Changed from 202 to 200 for sushi driver
                            response_body = json.dumps(response).encode("utf-8")
                            self.send_response(status_code)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(response_body)))
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(response_body)
                            _app.logger.debug(
                                f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}"
                            )
                            return
                    # END NEW CODE
                    if "Boot" in data:
                        boot_data = data["Boot"]
                        if "BootSourceOverrideMode" in boot_data:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.ActionNotSupported",
                                    "message": "Changing BootSourceOverrideMode is not supported through this resource. Use the Bios resource to change the boot mode.",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.ActionNotSupported",
                                            "Message": "The property BootSourceOverrideMode cannot be changed through the ComputerSystem resource. To change the boot mode, use a PATCH request to the Bios resource.",
                                            "Severity": "Warning",
                                            "Resolution": "Send a PATCH request to /redfish/v1/Systems/<vm_id>/Bios with the desired FirmwareMode in Attributes.",
                                        }
                                    ],
                                }
                            }
                        else:
                            target = boot_data.get("BootSourceOverrideTarget")
                            enabled = boot_data.get("BootSourceOverrideEnabled", "Once")
                            _app.logger.debug(f"Boot parameters: target={target}, enabled={enabled}")

                            if target not in ["Pxe", "Cd", "Hdd"]:
                                _app.logger.error(f"Invalid BootSourceOverrideTarget: {target}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideTarget: {target}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{target}' for BootSourceOverrideTarget is not in the supported list: Pxe, Cd, Hdd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported.",
                                            }
                                        ],
                                    }
                                }
                            elif enabled not in ["Once", "Continuous", "Disabled"]:
                                _app.logger.error(f"Invalid BootSourceOverrideEnabled: {enabled}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideEnabled: {enabled}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{enabled}' for BootSourceOverrideEnabled is not in the supported list: Once, Continuous, Disabled.",
                                                "MessageArgs": [enabled],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported value for BootSourceOverrideEnabled.",
                                            }
                                        ],
                                    }
                                }
                            # Check the VM's current power state
                            _app.logger.debug(f"Checking power state for VM {vm_id}")
                            try:
                                vm_resource = _app._get_vm_resource(proxmox, vm_id)
                                status = vm_resource.status.current.get()
                                _app.logger.debug(f"VM {vm_id} status: {status['status']}")
                            except Exception as e:
                                _app.logger.error(f"Failed to get VM {vm_id} status: {str(e)}")
                                status_code = 500
                                response = {
                                    "error": {
                                        "code": "Base.1.0.GeneralError",
                                        "message": f"Failed to get VM status: {str(e)}",
                                    }
                                }

                            redfish_status = {
                                "running": "On",
                                "stopped": "Off",
                                "paused": "Paused",
                                "shutdown": "Off",
                            }.get(status["status"], "Unknown")
                            _app.logger.debug(f"VM {vm_id} redfish_status: {redfish_status}")

                            # Proceed with boot order change
                            _app.logger.debug(f"VM {vm_id}, proceeding with boot order change to {target}")
                            try:
                                config = vm_resource.config.get()
                                current_boot = config.get("boot", "")
                                _app.logger.debug(f"Current boot order: {current_boot}")
                                new_boot_order = _app.reorder_boot_order(proxmox, int(vm_id), current_boot, target)
                                _app.logger.debug(f"New boot order: {new_boot_order}")
                                config_data = {"boot": f"order={new_boot_order}" if new_boot_order else ""}
                                task = vm_resource.config.post(**config_data)
                                _app.logger.debug(f"Boot order update task initiated: {task}")
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set Boot Order for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [
                                        {"Message": f"Boot order set to {target} ({new_boot_order}) for VM {vm_id}"}
                                    ],
                                }
                                status_code = 202
                            except ValueError as e:
                                _app.logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.ActionNotSupported",
                                        "message": f"Cannot set BootSourceOverrideTarget to {target}: {str(e)}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.ActionNotSupported",
                                                "Message": f"The requested boot device '{target}' is not available. Available boot devices are: Pxe, Cd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported or verify the VM configuration.",
                                            }
                                        ],
                                    }
                                }
                            except Exception as e:
                                _app.logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                response, status_code = _app.handle_proxmox_error("Boot configuration", e, vm_id)
                    else:
                        _app.logger.error("Boot object required in PATCH request")
                        status_code = 400
                        response = {
                            "error": {
                                "code": "Base.1.0.InvalidRequest",
                                "message": "Boot object required in PATCH request",
                            }
                        }
                except json.JSONDecodeError:
                    _app.logger.error("Invalid JSON payload")
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
            else:
                _app.logger.error(f"Resource not found: {path}")
                status_code = 404
                response = {
                    "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}
                }

        response_body = json.dumps(response).encode("utf-8")
        content_length = len(response_body)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

        _app.logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
