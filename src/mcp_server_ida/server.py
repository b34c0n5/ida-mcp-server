import logging
import socket
import json
import time
import struct
import uuid
from typing import Dict, Any, List, Union, Optional, Tuple, Callable, TypeVar, Set, Awaitable, Type, cast
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)
from enum import Enum
from pydantic import BaseModel

# Modify request models
class GetFunctionAssemblyByName(BaseModel):
    function_name: str

class GetFunctionAssemblyByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetFunctionDecompiledByName(BaseModel):
    function_name: str

class GetFunctionDecompiledByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetGlobalVariableByName(BaseModel):
    variable_name: str

class GetGlobalVariableByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetCurrentFunctionAssembly(BaseModel):
    pass

class GetCurrentFunctionDecompiled(BaseModel):
    pass

class RenameLocalVariable(BaseModel):
    function_name: str
    old_name: str
    new_name: str

class RenameGlobalVariable(BaseModel):
    old_name: str
    new_name: str

class RenameFunction(BaseModel):
    old_name: str
    new_name: str

class AddAssemblyComment(BaseModel):
    address: str  # Can be a hexadecimal address string
    comment: str
    is_repeatable: bool = False  # Whether the comment should be repeatable

class AddFunctionComment(BaseModel):
    function_name: str
    comment: str
    is_repeatable: bool = False  # Whether the comment should be repeatable

class AddPseudocodeComment(BaseModel):
    function_name: str
    address: str  # Address in the pseudocode
    comment: str
    is_repeatable: bool = False  # Whether comment should be repeated at all occurrences

class ExecuteScript(BaseModel):
    script: str

class ExecuteScriptFromFile(BaseModel):
    file_path: str

class IDATools(str, Enum):
    GET_FUNCTION_ASSEMBLY_BY_NAME = "ida_get_function_assembly_by_name"
    GET_FUNCTION_ASSEMBLY_BY_ADDRESS = "ida_get_function_assembly_by_address"
    GET_FUNCTION_DECOMPILED_BY_NAME = "ida_get_function_decompiled_by_name"
    GET_FUNCTION_DECOMPILED_BY_ADDRESS = "ida_get_function_decompiled_by_address"
    GET_GLOBAL_VARIABLE_BY_NAME = "ida_get_global_variable_by_name"
    GET_GLOBAL_VARIABLE_BY_ADDRESS = "ida_get_global_variable_by_address"
    GET_CURRENT_FUNCTION_ASSEMBLY = "ida_get_current_function_assembly"
    GET_CURRENT_FUNCTION_DECOMPILED = "ida_get_current_function_decompiled"
    RENAME_LOCAL_VARIABLE = "ida_rename_local_variable"
    RENAME_GLOBAL_VARIABLE = "ida_rename_global_variable"
    RENAME_FUNCTION = "ida_rename_function"
    ADD_ASSEMBLY_COMMENT = "ida_add_assembly_comment"
    ADD_FUNCTION_COMMENT = "ida_add_function_comment"
    ADD_PSEUDOCODE_COMMENT = "ida_add_pseudocode_comment"
    EXECUTE_SCRIPT = "ida_execute_script"
    EXECUTE_SCRIPT_FROM_FILE = "ida_execute_script_from_file"

# IDA Pro通信处理器
class IDAProCommunicator:
    def __init__(self, host: str = 'localhost', port: int = 5000):
        self.host: str = host
        self.port: int = port
        self.sock: Optional[socket.socket] = None
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.connected: bool = False
        self.reconnect_attempts: int = 0
        self.max_reconnect_attempts: int = 5
        self.last_reconnect_time: float = 0
        self.reconnect_cooldown: int = 5  # seconds
        self.request_count: int = 0
    
    def connect(self) -> bool:
        """Connect to IDA plugin"""
        # Check if cooldown is needed
        current_time: float = time.time()
        if current_time - self.last_reconnect_time < self.reconnect_cooldown and self.reconnect_attempts > 0:
            self.logger.debug("In reconnection cooldown, skipping")
            return False
            
        # If already connected, disconnect first
        if self.connected:
            self.disconnect()
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)  # Set timeout
            self.sock.connect((self.host, self.port))
            self.connected = True
            self.reconnect_attempts = 0
            self.logger.info(f"Connected to IDA Pro ({self.host}:{self.port})")
            return True
        except Exception as e:
            self.last_reconnect_time = current_time
            self.reconnect_attempts += 1
            if self.reconnect_attempts <= self.max_reconnect_attempts:
                self.logger.warning(f"Failed to connect to IDA Pro: {str(e)}. Attempt {self.reconnect_attempts}/{self.max_reconnect_attempts}")
            else:
                self.logger.error(f"Failed to connect to IDA Pro after {self.max_reconnect_attempts} attempts: {str(e)}")
            return False
    
    def disconnect(self) -> None:
        """Disconnect from IDA Pro"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False
    
    def ensure_connection(self) -> bool:
        """Ensure connection is established"""
        if not self.connected:
            return self.connect()
        return True
    
    def send_message(self, data: bytes) -> None:
        """Send message with length prefix"""
        if self.sock is None:
            raise ConnectionError("Socket is not connected")
            
        length: int = len(data)
        length_bytes: bytes = struct.pack('!I', length)  # 4-byte length prefix
        self.sock.sendall(length_bytes + data)
    
    def receive_message(self) -> Optional[bytes]:
        """Receive message with length prefix"""
        try:
            # Receive 4-byte length prefix
            length_bytes: Optional[bytes] = self.receive_exactly(4)
            if not length_bytes:
                return None
                
            length: int = struct.unpack('!I', length_bytes)[0]
            
            # Receive message body
            data: Optional[bytes] = self.receive_exactly(length)
            return data
        except Exception as e:
            self.logger.error(f"Error receiving message: {str(e)}")
            return None
    
    def receive_exactly(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes of data"""
        if self.sock is None:
            raise ConnectionError("Socket is not connected")
            
        data: bytes = b''
        while len(data) < n:
            chunk: bytes = self.sock.recv(min(n - len(data), 4096))
            if not chunk:  # Connection closed
                return None
            data += chunk
        return data
    
    def send_request(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to IDA plugin"""
        # Ensure connection is established
        if not self.ensure_connection():
            return {"error": "Cannot connect to IDA Pro"}
        
        # Add request ID
        request_id: str = str(uuid.uuid4())
        self.request_count += 1
        request_count: int = self.request_count
        
        request: Dict[str, Any] = {
            "id": request_id,
            "count": request_count,
            "type": request_type,
            "data": data
        }
        
        self.logger.debug(f"Sending request: {request_id}, type: {request_type}, count: {request_count}")
        
        try:
            # Send request
            request_json: bytes = json.dumps(request).encode('utf-8')
            self.send_message(request_json)
            
            # Receive response
            response_data: Optional[bytes] = self.receive_message()
            
            # If no data received, assume connection is closed
            if not response_data:
                self.logger.warning("No data received, connection may be closed")
                self.disconnect()
                return {"error": "No response received from IDA Pro"}
            
            # Parse response
            try:
                self.logger.debug(f"Received raw data length: {len(response_data)}")
                response: Dict[str, Any] = json.loads(response_data.decode('utf-8'))
                
                # Verify response ID matches
                response_id: str = response.get("id")
                if response_id != request_id:
                    self.logger.warning(f"Response ID mismatch! Request ID: {request_id}, Response ID: {response_id}")
                
                self.logger.debug(f"Received response: ID={response.get('id')}, count={response.get('count')}")
                
                # Additional type verification
                if not isinstance(response, dict):
                    self.logger.error(f"Received response is not a dictionary: {type(response)}")
                    return {"error": f"Response format error: expected dictionary, got {type(response).__name__}"}
                
                return response
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse JSON response: {str(e)}")
                return {"error": f"Invalid JSON response: {str(e)}"}
                
        except Exception as e:
            self.logger.error(f"Error communicating with IDA Pro: {str(e)}")
            self.disconnect()  # Disconnect after error
            return {"error": str(e)}
    
    def ping(self) -> bool:
        """Check if connection is valid"""
        response: Dict[str, Any] = self.send_request("ping", {})
        return response.get("status") == "pong"

# Actual IDA Pro functionality implementation
class IDAProFunctions:
    def __init__(self, communicator: IDAProCommunicator):
        self.communicator: IDAProCommunicator = communicator
        self.logger: logging.Logger = logging.getLogger(__name__)
        
    def get_function_assembly(self, function_name: str) -> str:
        """Get assembly code for a function by name (legacy method)"""
        return self.get_function_assembly_by_name(function_name)
        
    def get_function_assembly_by_name(self, function_name: str) -> str:
        """Get assembly code for a function by its name"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "get_function_assembly_by_name", 
                {"function_name": function_name}
            )
            
            if "error" in response:
                return f"Error retrieving assembly for function '{function_name}': {response['error']}"
            
            assembly: Any = response.get("assembly")
            # Verify assembly is string type
            if assembly is None:
                return f"Error: No assembly data returned for function '{function_name}'"
            if not isinstance(assembly, str):
                self.logger.warning(f"Assembly data type is not string but {type(assembly).__name__}, attempting conversion")
                assembly = str(assembly)
            
            return f"Assembly code for function '{function_name}':\n{assembly}"
        except Exception as e:
            self.logger.error(f"Error getting function assembly: {str(e)}", exc_info=True)
            return f"Error retrieving assembly for function '{function_name}': {str(e)}"
        
    def get_function_decompiled(self, function_name: str) -> str:
        """Get decompiled code for a function by name (legacy method)"""
        return self.get_function_decompiled_by_name(function_name)
    
    def get_function_decompiled_by_name(self, function_name: str) -> str:
        """Get decompiled pseudocode for a function by its name"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "get_function_decompiled_by_name", 
                {"function_name": function_name}
            )
            
            # Log complete response for debugging
            self.logger.debug(f"Decompilation response: {response}")
            
            if "error" in response:
                return f"Error retrieving decompiled code for function '{function_name}': {response['error']}"
            
            decompiled_code: Any = response.get("decompiled_code")
            
            # Detailed type checking and conversion
            if decompiled_code is None:
                return f"Error: No decompiled code returned for function '{function_name}'"
                
            # Log actual type
            actual_type: str = type(decompiled_code).__name__
            self.logger.debug(f"Decompiled code type is: {actual_type}")
            
            # Ensure result is string
            if not isinstance(decompiled_code, str):
                self.logger.warning(f"Decompiled code type is not string but {actual_type}, attempting conversion")
                try:
                    decompiled_code = str(decompiled_code)
                except Exception as e:
                    return f"Error: Failed to convert decompiled code from {actual_type} to string: {str(e)}"
            
            return f"Decompiled code for function '{function_name}':\n{decompiled_code}"
        except Exception as e:
            self.logger.error(f"Error getting function decompiled code: {str(e)}", exc_info=True)
            return f"Error retrieving decompiled code for function '{function_name}': {str(e)}"
    
    def get_global_variable(self, variable_name: str) -> str:
        """Get global variable information by name (legacy method)"""
        return self.get_global_variable_by_name(variable_name)
    
    def get_global_variable_by_name(self, variable_name: str) -> str:
        """Get global variable information by its name"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "get_global_variable_by_name", 
                {"variable_name": variable_name}
            )
            
            if "error" in response:
                return f"Error retrieving global variable '{variable_name}': {response['error']}"
            
            variable_info: Any = response.get("variable_info")
            
            # Verify variable_info is string type
            if variable_info is None:
                return f"Error: No variable info returned for '{variable_name}'"
            if not isinstance(variable_info, str):
                self.logger.warning(f"Variable info type is not string but {type(variable_info).__name__}, attempting conversion")
                try:
                    # If it's a dictionary, convert to JSON string first
                    if isinstance(variable_info, dict):
                        variable_info = json.dumps(variable_info, indent=2)
                    else:
                        variable_info = str(variable_info)
                except Exception as e:
                    return f"Error: Failed to convert variable info to string: {str(e)}"
            
            return f"Global variable '{variable_name}':\n{variable_info}"
        except Exception as e:
            self.logger.error(f"Error getting global variable: {str(e)}", exc_info=True)
            return f"Error retrieving global variable '{variable_name}': {str(e)}"
    
    def get_global_variable_by_address(self, address: str) -> str:
        """Get global variable information by its address"""
        try:
            # Convert string address to int
            try:
                addr_int = int(address, 16) if address.startswith("0x") else int(address)
            except ValueError:
                return f"Error: Invalid address format '{address}', expected hexadecimal (0x...) or decimal"
                
            response: Dict[str, Any] = self.communicator.send_request(
                "get_global_variable_by_address", 
                {"address": addr_int}
            )
            
            if "error" in response:
                return f"Error retrieving global variable at address '{address}': {response['error']}"
            
            variable_info: Any = response.get("variable_info")
            
            # Verify variable_info is string type
            if variable_info is None:
                return f"Error: No variable info returned for address '{address}'"
            if not isinstance(variable_info, str):
                self.logger.warning(f"Variable info type is not string but {type(variable_info).__name__}, attempting conversion")
                try:
                    # If it's a dictionary, convert to JSON string first
                    if isinstance(variable_info, dict):
                        variable_info = json.dumps(variable_info, indent=2)
                    else:
                        variable_info = str(variable_info)
                except Exception as e:
                    return f"Error: Failed to convert variable info to string: {str(e)}"
            
            # Try to extract the variable name from the JSON for a better message
            var_name = "Unknown"
            try:
                var_info_dict = json.loads(variable_info)
                if isinstance(var_info_dict, dict) and "name" in var_info_dict:
                    var_name = var_info_dict["name"]
            except:
                pass
            
            return f"Global variable '{var_name}' at address {address}:\n{variable_info}"
        except Exception as e:
            self.logger.error(f"Error getting global variable by address: {str(e)}", exc_info=True)
            return f"Error retrieving global variable at address '{address}': {str(e)}"
    
    def get_current_function_assembly(self) -> str:
        """Get assembly code for the function at current cursor position"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "get_current_function_assembly", 
                {}
            )
            
            if "error" in response:
                return f"Error retrieving assembly for current function: {response['error']}"
            
            assembly: Any = response.get("assembly")
            function_name: str = response.get("function_name", "Current function")
            
            # Verify assembly is string type
            if assembly is None:
                return f"Error: No assembly data returned for current function"
            if not isinstance(assembly, str):
                self.logger.warning(f"Assembly data type is not string but {type(assembly).__name__}, attempting conversion")
                assembly = str(assembly)
            
            return f"Assembly code for function '{function_name}':\n{assembly}"
        except Exception as e:
            self.logger.error(f"Error getting current function assembly: {str(e)}", exc_info=True)
            return f"Error retrieving assembly for current function: {str(e)}"
    
    def get_current_function_decompiled(self) -> str:
        """Get decompiled code for the function at current cursor position"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "get_current_function_decompiled", 
                {}
            )
            
            if "error" in response:
                return f"Error retrieving decompiled code for current function: {response['error']}"
            
            decompiled_code: Any = response.get("decompiled_code")
            function_name: str = response.get("function_name", "Current function")
            
            # Detailed type checking and conversion
            if decompiled_code is None:
                return f"Error: No decompiled code returned for current function"
                
            # Ensure result is string
            if not isinstance(decompiled_code, str):
                self.logger.warning(f"Decompiled code type is not string but {type(decompiled_code).__name__}, attempting conversion")
                try:
                    decompiled_code = str(decompiled_code)
                except Exception as e:
                    return f"Error: Failed to convert decompiled code: {str(e)}"
            
            return f"Decompiled code for function '{function_name}':\n{decompiled_code}"
        except Exception as e:
            self.logger.error(f"Error getting current function decompiled code: {str(e)}", exc_info=True)
            return f"Error retrieving decompiled code for current function: {str(e)}"

    def rename_local_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        """Rename a local variable within a function"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "rename_local_variable", 
                {"function_name": function_name, "old_name": old_name, "new_name": new_name}
            )
            
            if "error" in response:
                return f"Error renaming local variable from '{old_name}' to '{new_name}' in function '{function_name}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                return f"Successfully renamed local variable from '{old_name}' to '{new_name}' in function '{function_name}': {message}"
            else:
                return f"Failed to rename local variable from '{old_name}' to '{new_name}' in function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(f"Error renaming local variable: {str(e)}", exc_info=True)
            return f"Error renaming local variable from '{old_name}' to '{new_name}' in function '{function_name}': {str(e)}"

    def rename_global_variable(self, old_name: str, new_name: str) -> str:
        """Rename a global variable"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "rename_global_variable", 
                {"old_name": old_name, "new_name": new_name}
            )
            
            if "error" in response:
                return f"Error renaming global variable from '{old_name}' to '{new_name}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                return f"Successfully renamed global variable from '{old_name}' to '{new_name}': {message}"
            else:
                return f"Failed to rename global variable from '{old_name}' to '{new_name}': {message}"
        except Exception as e:
            self.logger.error(f"Error renaming global variable: {str(e)}", exc_info=True)
            return f"Error renaming global variable from '{old_name}' to '{new_name}': {str(e)}"

    def rename_function(self, old_name: str, new_name: str) -> str:
        """Rename a function"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "rename_function", 
                {"old_name": old_name, "new_name": new_name}
            )
            
            if "error" in response:
                return f"Error renaming function from '{old_name}' to '{new_name}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                return f"Successfully renamed function from '{old_name}' to '{new_name}': {message}"
            else:
                return f"Failed to rename function from '{old_name}' to '{new_name}': {message}"
        except Exception as e:
            self.logger.error(f"Error renaming function: {str(e)}", exc_info=True)
            return f"Error renaming function from '{old_name}' to '{new_name}': {str(e)}"

    def add_assembly_comment(self, address: str, comment: str, is_repeatable: bool = False) -> str:
        """Add an assembly comment"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "add_assembly_comment", 
                {"address": address, "comment": comment, "is_repeatable": is_repeatable}
            )
            
            if "error" in response:
                return f"Error adding assembly comment at address '{address}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} assembly comment at address '{address}': {message}"
            else:
                return f"Failed to add assembly comment at address '{address}': {message}"
        except Exception as e:
            self.logger.error(f"Error adding assembly comment: {str(e)}", exc_info=True)
            return f"Error adding assembly comment at address '{address}': {str(e)}"

    def add_function_comment(self, function_name: str, comment: str, is_repeatable: bool = False) -> str:
        """Add a comment to a function"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "add_function_comment", 
                {"function_name": function_name, "comment": comment, "is_repeatable": is_repeatable}
            )
            
            if "error" in response:
                return f"Error adding comment to function '{function_name}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} comment to function '{function_name}': {message}"
            else:
                return f"Failed to add comment to function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(f"Error adding function comment: {str(e)}", exc_info=True)
            return f"Error adding comment to function '{function_name}': {str(e)}"

    def add_pseudocode_comment(self, function_name: str, address: str, comment: str, is_repeatable: bool = False) -> str:
        """Add a comment to a specific address in the function's decompiled pseudocode"""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "add_pseudocode_comment",
                {
                    "function_name": function_name,
                    "address": address,
                    "comment": comment,
                    "is_repeatable": is_repeatable
                }
            )
            
            if "error" in response:
                return f"Error adding comment at address {address} in function '{function_name}': {response['error']}"
            
            success: bool = response.get("success", False)
            message: str = response.get("message", "")
            
            if success:
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return f"Successfully added {comment_type} comment at address {address} in function '{function_name}': {message}"
            else:
                return f"Failed to add comment at address {address} in function '{function_name}': {message}"
        except Exception as e:
            self.logger.error(f"Error adding pseudocode comment: {str(e)}", exc_info=True)
            return f"Error adding comment at address {address} in function '{function_name}': {str(e)}"

    def execute_script(self, script: str) -> str:
        """Execute a Python script in IDA Pro and return its output. The script runs in IDA's context with access to all IDA API modules."""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "execute_script",
                {"script": script}
            )
            
            # Handle case where response is None
            if response is None:
                self.logger.error("Received None response from IDA when executing script")
                return "Error executing script: Received empty response from IDA"
                
            # Handle case where response contains error
            if "error" in response:
                return f"Error executing script: {response['error']}"
            
            # Handle successful execution
            success: bool = response.get("success", False)
            if not success:
                error_msg: str = response.get("error", "Unknown error")
                traceback: str = response.get("traceback", "")
                return f"Script execution failed: {error_msg}\n\nTraceback:\n{traceback}"
            
            # Get output - ensure all values are strings to avoid None errors
            stdout: str = str(response.get("stdout", ""))
            stderr: str = str(response.get("stderr", ""))
            return_value: str = str(response.get("return_value", ""))
            
            result_text: List[str] = []
            result_text.append("Script executed successfully")
            
            if return_value and return_value != "None":
                result_text.append(f"\nReturn value:\n{return_value}")
            
            if stdout:
                result_text.append(f"\nStandard output:\n{stdout}")
            
            if stderr:
                result_text.append(f"\nStandard error:\n{stderr}")
            
            return "\n".join(result_text)
            
        except Exception as e:
            self.logger.error(f"Error executing script: {str(e)}", exc_info=True)
            return f"Error executing script: {str(e)}"

    def execute_script_from_file(self, file_path: str) -> str:
        """Execute a Python script from a file path in IDA Pro and return its output. The file should be accessible from IDA's process."""
        try:
            response: Dict[str, Any] = self.communicator.send_request(
                "execute_script_from_file",
                {"file_path": file_path}
            )
            
            # Handle case where response is None
            if response is None:
                self.logger.error("Received None response from IDA when executing script from file")
                return f"Error executing script from file '{file_path}': Received empty response from IDA"
                
            # Handle case where response contains error
            if "error" in response:
                return f"Error executing script from file '{file_path}': {response['error']}"
            
            # Handle successful execution
            success: bool = response.get("success", False)
            if not success:
                error_msg: str = response.get("error", "Unknown error")
                traceback: str = response.get("traceback", "")
                return f"Script execution from file '{file_path}' failed: {error_msg}\n\nTraceback:\n{traceback}"
            
            # Get output - ensure all values are strings to avoid None errors
            stdout: str = str(response.get("stdout", ""))
            stderr: str = str(response.get("stderr", ""))
            return_value: str = str(response.get("return_value", ""))
            
            result_text: List[str] = []
            result_text.append(f"Script from file '{file_path}' executed successfully")
            
            if return_value and return_value != "None":
                result_text.append(f"\nReturn value:\n{return_value}")
            
            if stdout:
                result_text.append(f"\nStandard output:\n{stdout}")
            
            if stderr:
                result_text.append(f"\nStandard error:\n{stderr}")
            
            return "\n".join(result_text)
            
        except Exception as e:
            self.logger.error(f"Error executing script from file: {str(e)}", exc_info=True)
            return f"Error executing script from file '{file_path}': {str(e)}"

    def get_function_assembly_by_address(self, address: str) -> str:
        """Get assembly code for a function by its address"""
        try:
            # Convert string address to int
            try:
                addr_int = int(address, 16) if address.startswith("0x") else int(address)
            except ValueError:
                return f"Error: Invalid address format '{address}', expected hexadecimal (0x...) or decimal"
                
            response: Dict[str, Any] = self.communicator.send_request(
                "get_function_assembly_by_address", 
                {"address": addr_int}
            )
            
            if "error" in response:
                return f"Error retrieving assembly for address '{address}': {response['error']}"
            
            assembly: Any = response.get("assembly")
            function_name: str = response.get("function_name", "Unknown function")
            
            # Verify assembly is string type
            if assembly is None:
                return f"Error: No assembly data returned for address '{address}'"
            if not isinstance(assembly, str):
                self.logger.warning(f"Assembly data type is not string but {type(assembly).__name__}, attempting conversion")
                assembly = str(assembly)
            
            return f"Assembly code for function '{function_name}' at address {address}:\n{assembly}"
        except Exception as e:
            self.logger.error(f"Error getting function assembly by address: {str(e)}", exc_info=True)
            return f"Error retrieving assembly for address '{address}': {str(e)}"
    
    def get_function_decompiled_by_address(self, address: str) -> str:
        """Get decompiled pseudocode for a function by its address"""
        try:
            # Convert string address to int
            try:
                addr_int = int(address, 16) if address.startswith("0x") else int(address)
            except ValueError:
                return f"Error: Invalid address format '{address}', expected hexadecimal (0x...) or decimal"
                
            response: Dict[str, Any] = self.communicator.send_request(
                "get_function_decompiled_by_address", 
                {"address": addr_int}
            )
            
            if "error" in response:
                return f"Error retrieving decompiled code for address '{address}': {response['error']}"
            
            decompiled_code: Any = response.get("decompiled_code")
            function_name: str = response.get("function_name", "Unknown function")
            
            # Detailed type checking and conversion
            if decompiled_code is None:
                return f"Error: No decompiled code returned for address '{address}'"
                
            # Ensure result is string
            if not isinstance(decompiled_code, str):
                self.logger.warning(f"Decompiled code type is not string but {type(decompiled_code).__name__}, attempting conversion")
                try:
                    decompiled_code = str(decompiled_code)
                except Exception as e:
                    return f"Error: Failed to convert decompiled code: {str(e)}"
            
            return f"Decompiled code for function '{function_name}' at address {address}:\n{decompiled_code}"
        except Exception as e:
            self.logger.error(f"Error getting function decompiled code by address: {str(e)}", exc_info=True)
            return f"Error retrieving decompiled code for address '{address}': {str(e)}"

async def serve() -> None:
    """MCP server main entry point"""
    logger: logging.Logger = logging.getLogger(__name__)
    # Set log level to DEBUG for detailed information
    logger.setLevel(logging.DEBUG)
    server: Server = Server("mcp-ida")
    
    # Create communicator and attempt connection
    ida_communicator: IDAProCommunicator = IDAProCommunicator()
    logger.info("Attempting to connect to IDA Pro plugin...")
    
    if ida_communicator.connect():
        logger.info("Successfully connected to IDA Pro plugin")
    else:
        logger.warning("Initial connection to IDA Pro plugin failed, will retry on request")
    
    # Create IDA functions class with persistent connection
    ida_functions: IDAProFunctions = IDAProFunctions(ida_communicator)

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        """List supported tools"""
        return [
            Tool(
                name=IDATools.GET_FUNCTION_ASSEMBLY_BY_NAME,
                description="Get assembly code for a function by name",
                inputSchema=GetFunctionAssemblyByName.schema(),
            ),
            Tool(
                name=IDATools.GET_FUNCTION_ASSEMBLY_BY_ADDRESS,
                description="Get assembly code for a function by address",
                inputSchema=GetFunctionAssemblyByAddress.schema(),
            ),
            Tool(
                name=IDATools.GET_FUNCTION_DECOMPILED_BY_NAME,
                description="Get decompiled pseudocode for a function by name",
                inputSchema=GetFunctionDecompiledByName.schema(),
            ),
            Tool(
                name=IDATools.GET_FUNCTION_DECOMPILED_BY_ADDRESS,
                description="Get decompiled pseudocode for a function by address",
                inputSchema=GetFunctionDecompiledByAddress.schema(),
            ),
            Tool(
                name=IDATools.GET_GLOBAL_VARIABLE_BY_NAME,
                description="Get information about a global variable by name",
                inputSchema=GetGlobalVariableByName.schema(),
            ),
            Tool(
                name=IDATools.GET_GLOBAL_VARIABLE_BY_ADDRESS,
                description="Get information about a global variable by address",
                inputSchema=GetGlobalVariableByAddress.schema(),
            ),
            Tool(
                name=IDATools.GET_CURRENT_FUNCTION_ASSEMBLY,
                description="Get assembly code for the function at the current cursor position",
                inputSchema=GetCurrentFunctionAssembly.schema(),
            ),
            Tool(
                name=IDATools.GET_CURRENT_FUNCTION_DECOMPILED,
                description="Get decompiled pseudocode for the function at the current cursor position",
                inputSchema=GetCurrentFunctionDecompiled.schema(),
            ),
            Tool(
                name=IDATools.RENAME_LOCAL_VARIABLE,
                description="Rename a local variable within a function in the IDA database",
                inputSchema=RenameLocalVariable.schema(),
            ),
            Tool(
                name=IDATools.RENAME_GLOBAL_VARIABLE,
                description="Rename a global variable in the IDA database",
                inputSchema=RenameGlobalVariable.schema(),
            ),
            Tool(
                name=IDATools.RENAME_FUNCTION,
                description="Rename a function in the IDA database",
                inputSchema=RenameFunction.schema(),
            ),
            Tool(
                name=IDATools.ADD_ASSEMBLY_COMMENT,
                description="Add a comment at a specific address in the assembly view of the IDA database",
                inputSchema=AddAssemblyComment.schema(),
            ),
            Tool(
                name=IDATools.ADD_FUNCTION_COMMENT,
                description="Add a comment to a function in the IDA database",
                inputSchema=AddFunctionComment.schema(),
            ),
            Tool(
                name=IDATools.ADD_PSEUDOCODE_COMMENT,
                description="Add a comment to a specific address in the function's decompiled pseudocode",
                inputSchema=AddPseudocodeComment.schema(),
            ),
            Tool(
                name=IDATools.EXECUTE_SCRIPT,
                description="Execute a Python script in IDA Pro and return its output. The script runs in IDA's context with access to all IDA API modules.",
                inputSchema=ExecuteScript.schema(),
            ),
            Tool(
                name=IDATools.EXECUTE_SCRIPT_FROM_FILE,
                description="Execute a Python script from a file path in IDA Pro and return its output. The file should be accessible from IDA's process.",
                inputSchema=ExecuteScriptFromFile.schema(),
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        """Call tool and handle results"""
        # Ensure connection exists
        if not ida_communicator.connected and not ida_communicator.ensure_connection():
            return [TextContent(
                type="text",
                text=f"Error: Cannot connect to IDA Pro plugin. Please ensure the plugin is running."
            )]
            
        try:
            match name:
                case IDATools.GET_FUNCTION_ASSEMBLY_BY_NAME:
                    assembly: str = ida_functions.get_function_assembly_by_name(arguments["function_name"])
                    return [TextContent(
                        type="text",
                        text=assembly
                    )]

                case IDATools.GET_FUNCTION_ASSEMBLY_BY_ADDRESS:
                    assembly: str = ida_functions.get_function_assembly_by_address(arguments["address"])
                    return [TextContent(
                        type="text",
                        text=assembly
                    )]

                case IDATools.GET_FUNCTION_DECOMPILED_BY_NAME:
                    decompiled: str = ida_functions.get_function_decompiled_by_name(arguments["function_name"])
                    return [TextContent(
                        type="text",
                        text=decompiled
                    )]

                case IDATools.GET_FUNCTION_DECOMPILED_BY_ADDRESS:
                    decompiled: str = ida_functions.get_function_decompiled_by_address(arguments["address"])
                    return [TextContent(
                        type="text",
                        text=decompiled
                    )]

                case IDATools.GET_GLOBAL_VARIABLE_BY_NAME:
                    variable_info: str = ida_functions.get_global_variable_by_name(arguments["variable_name"])
                    return [TextContent(
                        type="text",
                        text=variable_info
                    )]
                    
                case IDATools.GET_GLOBAL_VARIABLE_BY_ADDRESS:
                    variable_info: str = ida_functions.get_global_variable_by_address(arguments["address"])
                    return [TextContent(
                        type="text",
                        text=variable_info
                    )]

                case IDATools.GET_CURRENT_FUNCTION_ASSEMBLY:
                    assembly: str = ida_functions.get_current_function_assembly()
                    return [TextContent(
                        type="text",
                        text=assembly
                    )]
                
                case IDATools.GET_CURRENT_FUNCTION_DECOMPILED:
                    decompiled: str = ida_functions.get_current_function_decompiled()
                    return [TextContent(
                        type="text",
                        text=decompiled
                    )]

                case IDATools.RENAME_LOCAL_VARIABLE:
                    result: str = ida_functions.rename_local_variable(
                        arguments["function_name"],
                        arguments["old_name"], 
                        arguments["new_name"]
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.RENAME_GLOBAL_VARIABLE:
                    result: str = ida_functions.rename_global_variable(
                        arguments["old_name"], 
                        arguments["new_name"]
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.RENAME_FUNCTION:
                    result: str = ida_functions.rename_function(
                        arguments["old_name"], 
                        arguments["new_name"]
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.ADD_ASSEMBLY_COMMENT:
                    result: str = ida_functions.add_assembly_comment(
                        arguments["address"], 
                        arguments["comment"], 
                        arguments.get("is_repeatable", False)
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.ADD_FUNCTION_COMMENT:
                    result: str = ida_functions.add_function_comment(
                        arguments["function_name"], 
                        arguments["comment"], 
                        arguments.get("is_repeatable", False)
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.ADD_PSEUDOCODE_COMMENT:
                    result: str = ida_functions.add_pseudocode_comment(
                        arguments["function_name"],
                        arguments["address"],
                        arguments["comment"],
                        arguments.get("is_repeatable", False)
                    )
                    return [TextContent(
                        type="text",
                        text=result
                    )]

                case IDATools.EXECUTE_SCRIPT:
                    try:
                        if "script" not in arguments or not arguments["script"]:
                            return [TextContent(
                                type="text",
                                text="Error: No script content provided"
                            )]
                            
                        result: str = ida_functions.execute_script(arguments["script"])
                        return [TextContent(
                            type="text",
                            text=result
                        )]
                    except Exception as e:
                        logger.error(f"Error executing script: {str(e)}", exc_info=True)
                        return [TextContent(
                            type="text",
                            text=f"Error executing script: {str(e)}"
                        )]

                case IDATools.EXECUTE_SCRIPT_FROM_FILE:
                    try:
                        if "file_path" not in arguments or not arguments["file_path"]:
                            return [TextContent(
                                type="text",
                                text="Error: No file path provided"
                            )]
                            
                        result: str = ida_functions.execute_script_from_file(arguments["file_path"])
                        return [TextContent(
                            type="text",
                            text=result
                        )]
                    except Exception as e:
                        logger.error(f"Error executing script from file: {str(e)}", exc_info=True)
                        return [TextContent(
                            type="text",
                            text=f"Error executing script from file: {str(e)}"
                        )]

                case _:
                    raise ValueError(f"Unknown tool: {name}")
        except Exception as e:
            logger.error(f"Error calling tool: {str(e)}", exc_info=True)
            return [TextContent(
                type="text",
                text=f"Error executing {name}: {str(e)}"
            )]

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)
