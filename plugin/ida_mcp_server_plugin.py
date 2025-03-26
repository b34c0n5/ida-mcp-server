import idaapi
import json
import socket
import struct
import threading
import traceback
import time
from ida_mcp_server_plugin.ida_mcp_core import IDAMCPCore

PLUGIN_NAME = "IDA MCP Server"
PLUGIN_HOTKEY = "Ctrl-Alt-M"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "IDA MCP"

# Default configuration
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000

class IDACommunicator:
    """IDA Communication class"""
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = None
    
    def connect(self):
        pass

class IDAMCPServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        self.client_counter = 0
        self.core = IDAMCPCore()
    
    def start(self):
        """Start Socket server"""
        if self.running:
            print("MCP Server already running")
            return False
            
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Set timeout to allow server to respond to stop requests
            
            self.running = True
            self.thread = threading.Thread(target=self.server_loop)
            self.thread.daemon = True
            self.thread.start()
            
            print(f"MCP Server started on {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Failed to start MCP Server: {str(e)}")
            traceback.print_exc()
            return False
    
    def stop(self):
        """Stop Socket server"""
        if not self.running:
            print("MCP Server is not running, no need to stop")
            return
            
        print("Stopping MCP Server...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"Error closing server socket: {str(e)}")
            self.server_socket = None
        
        if self.thread:
            try:
                self.thread.join(2.0)  # Wait for thread to end, maximum 2 seconds
            except Exception as e:
                print(f"Error joining server thread: {str(e)}")
            self.thread = None
            
        print("MCP Server stopped")
    
    def send_message(self, client_socket, data: bytes) -> None:
        """Send message with length prefix"""
        length = len(data)
        length_bytes = struct.pack('!I', length)  # 4-byte length prefix
        client_socket.sendall(length_bytes + data)

    def receive_message(self, client_socket) -> bytes:
        """Receive message with length prefix"""
        # Receive 4-byte length prefix
        length_bytes = self.receive_exactly(client_socket, 4)
        if not length_bytes:
            raise ConnectionError("Connection closed")
            
        length = struct.unpack('!I', length_bytes)[0]
        
        # Receive message body
        data = self.receive_exactly(client_socket, length)
        return data

    def receive_exactly(self, client_socket, n: int) -> bytes:
        """Receive exactly n bytes of data"""
        data = b''
        while len(data) < n:
            chunk = client_socket.recv(min(n - len(data), 4096))
            if not chunk:  # Connection closed
                raise ConnectionError("Connection closed, unable to receive complete data")
            data += chunk
        return data
    
    def server_loop(self):
        """Server main loop"""
        print("Server loop started")
        while self.running:
            try:
                # Use timeout receive to periodically check running flag
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.client_counter += 1
                    client_id = self.client_counter
                    print(f"Client #{client_id} connected from {client_address}")
                    
                    # Handle client request - use thread to support multiple clients
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    # Timeout is just for periodically checking running flag
                    continue
                except OSError as e:
                    if self.running:  # Only print error if server is running
                        if e.errno == 9:  # Bad file descriptor, usually means socket is closed
                            print("Server socket was closed")
                            break
                        print(f"Socket error: {str(e)}")
                except Exception as e:
                    if self.running:  # Only print error if server is running
                        print(f"Error accepting connection: {str(e)}")
                        traceback.print_exc()
            except Exception as e:
                if self.running:
                    print(f"Error in server loop: {str(e)}")
                    traceback.print_exc()
                time.sleep(1)  # Avoid high CPU usage
        
        print("Server loop ended")
    
    def handle_client(self, client_socket, client_id):
        """Handle client requests"""
        try:
            # Set timeout
            client_socket.settimeout(30)
            
            while self.running:
                try:
                    # Receive message
                    data = self.receive_message(client_socket)
                    
                    # Parse request
                    request = json.loads(data.decode('utf-8'))
                    request_type = request.get('type')
                    request_data = request.get('data', {})
                    request_id = request.get('id', 'unknown')
                    request_count = request.get('count', -1)
                    
                    print(f"Client #{client_id} request: {request_type}, ID: {request_id}, Count: {request_count}")
                    
                    # Handle different types of requests
                    response = {
                        "id": request_id,  # Return same request ID
                        "count": request_count  # Return same request count
                    }
                    
                    if request_type == "get_function_assembly":
                        response.update(self.core.get_function_assembly(request_data.get("function_name", "")))
                    elif request_type == "get_function_decompiled":
                        response.update(self.core.get_function_decompiled(request_data.get("function_name", "")))
                    elif request_type == "get_global_variable":
                        response.update(self.core.get_global_variable(request_data.get("variable_name", "")))
                    elif request_type == "get_current_function_assembly":
                        response.update(self.core.get_current_function_assembly())
                    elif request_type == "get_current_function_decompiled":
                        response.update(self.core.get_current_function_decompiled())
                    elif request_type == "rename_global_variable":
                        response.update(self.core.rename_global_variable(
                            request_data.get("old_name", ""),
                            request_data.get("new_name", "")
                        ))
                    elif request_type == "rename_function":
                        response.update(self.core.rename_function(
                            request_data.get("old_name", ""),
                            request_data.get("new_name", "")
                        ))
                    elif request_type == "add_assembly_comment":
                        response.update(self.core.add_assembly_comment(
                            request_data.get("address", ""),
                            request_data.get("comment", ""),
                            request_data.get("is_repeatable", False)
                        ))
                    elif request_type == "rename_local_variable":
                        response.update(self.core.rename_local_variable(
                            request_data.get("function_name", ""),
                            request_data.get("old_name", ""),
                            request_data.get("new_name", "")
                        ))
                    elif request_type == "add_function_comment":
                        response.update(self.core.add_function_comment(
                            request_data.get("function_name", ""),
                            request_data.get("comment", ""),
                            request_data.get("is_repeatable", False)
                        ))
                    elif request_type == "ping":
                        response["status"] = "pong"
                    elif request_type == "add_pseudocode_comment":
                        response.update(self.core.add_pseudocode_comment(
                            request_data.get("function_name", ""),
                            request_data.get("address", ""),
                            request_data.get("comment", ""),
                            request_data.get("is_repeatable", False)
                        ))
                    elif request_type == "refresh_view":
                        response.update(self.core.refresh_view())
                    else:
                        response["error"] = f"Unknown request type: {request_type}"
                    
                    # Verify response is correct
                    if not isinstance(response, dict):
                        print(f"Response is not a dictionary: {type(response).__name__}")
                        response = {
                            "id": request_id,
                            "count": request_count,
                            "error": f"Internal server error: response is not a dictionary but {type(response).__name__}"
                        }
                    
                    # Ensure all values in response are serializable
                    for key, value in list(response.items()):
                        if value is None:
                            response[key] = "null"
                        elif not isinstance(value, (str, int, float, bool, list, dict, tuple)):
                            print(f"Response key '{key}' has non-serializable type: {type(value).__name__}")
                            response[key] = str(value)
                        
                    # Send response
                    response_json = json.dumps(response).encode('utf-8')
                    self.send_message(client_socket, response_json)
                    print(f"Sent response to client #{client_id}, ID: {request_id}, Count: {request_count}")
                    
                except ConnectionError as e:
                    print(f"Connection with client #{client_id} lost: {str(e)}")
                    return
                except socket.timeout:
                    # print(f"Socket timeout with client #{client_id}")
                    continue
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON request from client #{client_id}: {str(e)}")
                    try:
                        response = {
                            "error": f"Invalid JSON request: {str(e)}"
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
                    except:
                        print(f"Failed to send error response to client #{client_id}")
                except Exception as e:
                    print(f"Error processing request from client #{client_id}: {str(e)}")
                    traceback.print_exc()
                    try:
                        response = {
                            "error": str(e)
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
                    except:
                        print(f"Failed to send error response to client #{client_id}")
                
        except Exception as e:
            print(f"Error handling client #{client_id}: {str(e)}")
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
            print(f"Client #{client_id} connection closed")
    

# IDA Plugin class
class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA MCP Server Plugin"
    help = "Provides MCP server functionality for IDA"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def __init__(self):
        super(IDAMCPPlugin, self).__init__()
        self.server = None
        self.initialized = False
        self.menu_items_added = False
        print(f"IDAMCPPlugin instance created")
    
    def init(self):
        """Plugin initialization"""
        try:
            print(f"{PLUGIN_NAME} v{PLUGIN_VERSION} by {PLUGIN_AUTHOR}")
            print("Initializing plugin...")
            
            # Add menu items
            if not self.menu_items_added:
                self.create_menu_items()
                self.menu_items_added = True
                print("Menu items added")
            
            # Mark as initialized
            self.initialized = True
            print("Plugin initialized successfully")
            
            # Delay server start to avoid initialization issues
            idaapi.register_timer(500, self._delayed_server_start)
            
            return idaapi.PLUGIN_KEEP
        except Exception as e:
            print(f"Error initializing plugin: {str(e)}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP
    
    def _delayed_server_start(self):
        """Delayed server start to avoid initialization race conditions"""
        try:
            if not self.server or not self.server.running:
                print("Delayed server start...")
                self.start_server()
        except Exception as e:
            print(f"Error in delayed server start: {str(e)}")
            traceback.print_exc()
        return -1  # Don't repeat
    
    def create_menu_items(self):
        """Create plugin menu items"""
        # Create menu items
        menu_path = "Edit/Plugins/"
        
        class StartServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin):
                idaapi.action_handler_t.__init__(self)
                self.plugin = plugin
            
            def activate(self, ctx):
                self.plugin.start_server()
                return 1
            
            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS
        
        class StopServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin):
                idaapi.action_handler_t.__init__(self)
                self.plugin = plugin
            
            def activate(self, ctx):
                self.plugin.stop_server()
                return 1
            
            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS
        
        try:
            # Register and add start server action
            start_action_name = "mcp:start_server"
            start_action_desc = idaapi.action_desc_t(
                start_action_name,
                "Start MCP Server",
                StartServerHandler(self),
                "Ctrl+Alt+S",
                "Start the MCP Server",
                199  # Icon ID
            )
            
            # Register and add stop server action
            stop_action_name = "mcp:stop_server"
            stop_action_desc = idaapi.action_desc_t(
                stop_action_name, 
                "Stop MCP Server",
                StopServerHandler(self),
                "Ctrl+Alt+X",
                "Stop the MCP Server",
                200  # Icon ID
            )
            
            # Register actions
            if not idaapi.register_action(start_action_desc):
                print("Failed to register start server action")
            if not idaapi.register_action(stop_action_desc):
                print("Failed to register stop server action")
            
            # Add to menu
            if not idaapi.attach_action_to_menu(menu_path + "Start MCP Server", start_action_name, idaapi.SETMENU_APP):
                print("Failed to attach start server action to menu")
            if not idaapi.attach_action_to_menu(menu_path + "Stop MCP Server", stop_action_name, idaapi.SETMENU_APP):
                print("Failed to attach stop server action to menu")
                
            print("Menu items created successfully")
        except Exception as e:
            print(f"Error creating menu items: {str(e)}")
            traceback.print_exc()
    
    def start_server(self):
        """Start server"""
        if self.server and self.server.running:
            print("MCP Server is already running")
            return
        
        try:
            print("Creating MCP Server instance...")
            self.server = IDAMCPServer()
            print("Starting MCP Server...")
            if self.server.start():
                print("MCP Server started successfully")
            else:
                print("Failed to start MCP Server")
        except Exception as e:
            print(f"Error starting server: {str(e)}")
            traceback.print_exc()
    
    def stop_server(self):
        """Stop server"""
        if not self.server:
            print("MCP Server instance does not exist")
            return
            
        if not self.server.running:
            print("MCP Server is not running")
            return
        
        try:
            self.server.stop()
            print("MCP Server stopped by user")
        except Exception as e:
            print(f"Error stopping server: {str(e)}")
            traceback.print_exc()
    
    def run(self, arg):
        """Execute when hotkey is pressed"""
        if not self.initialized:
            print("Plugin not initialized")
            return
        
        # Automatically start or stop server when hotkey is triggered
        try:
            if not self.server or not self.server.running:
                print("Hotkey triggered: starting server")
                self.start_server()
            else:
                print("Hotkey triggered: stopping server")
                self.stop_server()
        except Exception as e:
            print(f"Error in run method: {str(e)}")
            traceback.print_exc()
    
    def term(self):
        """Plugin termination"""
        try:
            if self.server and self.server.running:
                print("Terminating plugin: stopping server")
                self.server.stop()
            print(f"{PLUGIN_NAME} terminated")
        except Exception as e:
            print(f"Error terminating plugin: {str(e)}")
            traceback.print_exc()

# Register plugin
def PLUGIN_ENTRY():
    return IDAMCPPlugin()
