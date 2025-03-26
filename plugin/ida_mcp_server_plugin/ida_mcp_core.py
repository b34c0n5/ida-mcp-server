import idaapi
import idautils
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_name
import ida_segment
import ida_lines
import idc
import json
import traceback
import functools
import queue
from typing import Any, Callable, TypeVar, Optional, Dict, List, Union, Tuple, Type

# Type variable for function return type
T = TypeVar('T')

class IDASyncError(Exception):
    """Exception raised for IDA synchronization errors"""
    pass

# Global call stack to track synchronization calls
call_stack: queue.LifoQueue[str] = queue.LifoQueue()

def sync_wrapper(func: Callable[..., T], sync_type: int) -> T:
    """
    Wrapper function to execute a function in IDA's main thread
    
    Args:
        func: The function to execute
        sync_type: Synchronization type (MFF_READ or MFF_WRITE)
        
    Returns:
        The result of the function execution
    """
    if sync_type not in [idaapi.MFF_READ, idaapi.MFF_WRITE]:
        error_str = f'Invalid sync type {sync_type} for function {func.__name__}'
        print(error_str)
        raise IDASyncError(error_str)
    
    # Container for the result
    result_container: queue.Queue[Any] = queue.Queue()
    
    def execute_in_main_thread() -> int:
        # Check if we're already inside a sync_wrapper call
        if not call_stack.empty():
            last_func = call_stack.get()
            error_str = f'Nested sync call detected: function {func.__name__} called from {last_func}'
            print(error_str)
            call_stack.put(last_func)  # Put it back
            raise IDASyncError(error_str)
        
        # Add function to call stack
        call_stack.put(func.__name__)
        
        try:
            # Execute function and store result
            result_container.put(func())
        except Exception as e:
            print(f"Error in {func.__name__}: {str(e)}")
            traceback.print_exc()
            result_container.put(None)
        finally:
            # Always remove function from call stack
            call_stack.get()
        
        return 1  # Required by execute_sync
    
    # Execute in IDA's main thread
    idaapi.execute_sync(execute_in_main_thread, sync_type)
    
    # Return the result
    return result_container.get()

def idaread(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator for functions that read from the IDA database
    
    Args:
        func: The function to decorate
        
    Returns:
        Decorated function that executes in IDA's main thread with read access
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        # Create a partial function with the arguments
        partial_func = functools.partial(func, *args, **kwargs)
        # Preserve the original function name
        partial_func.__name__ = func.__name__
        # Execute with sync_wrapper
        return sync_wrapper(partial_func, idaapi.MFF_READ)
    
    return wrapper

def idawrite(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator for functions that write to the IDA database
    
    Args:
        func: The function to decorate
        
    Returns:
        Decorated function that executes in IDA's main thread with write access
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        # Create a partial function with the arguments
        partial_func = functools.partial(func, *args, **kwargs)
        # Preserve the original function name
        partial_func.__name__ = func.__name__
        # Execute with sync_wrapper
        return sync_wrapper(partial_func, idaapi.MFF_WRITE)
    
    return wrapper

class IDAMCPCore:
    """Core functionality implementation class for IDA MCP"""
    
    @idaread
    def get_function_assembly_by_name(self, function_name: str) -> Dict[str, Any]:
        """Get assembly code for a function by its name"""
        try:
            # Get function address from name
            func = idaapi.get_func(idaapi.get_name_ea(0, function_name))
            if not func:
                return {"error": f"Function '{function_name}' not found"}
            
            # Call address-based implementation
            result = self.get_function_assembly_by_address(func.start_ea)
            
            # If successful, add function name to result
            if "error" not in result:
                result["function_name"] = function_name
                
            return result
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_function_assembly_by_address(self, address: int) -> Dict[str, Any]:
        """Get assembly code for a function by its address"""
        try:
            # Get function from address
            func = idaapi.get_func(address)
            if not func:
                return {"error": f"No function found at address 0x{address:X}"}
            
            # Get function name
            func_name = idaapi.get_func_name(func.start_ea)
            
            # Generate assembly
            assembly = []
            
            # Create instruction iterator
            instruction_iterator = idaapi.func_item_iterator_t(func)
            
            # Get first instruction
            address = instruction_iterator.first()
            
            # Iterate through all instructions
            while address != idaapi.BADADDR:
                # Get disassembly line
                disasm_line = idaapi.generate_disasm_line(address, 0)
                
                # Get comment, if any
                comment = idaapi.get_cmt(address, 0)  # 0 for non-repeatable comment
                if not comment:
                    comment = idaapi.get_cmt(address, 1)  # 1 for repeatable comment
                
                # Add line with comment
                if comment:
                    assembly.append(f"{disasm_line} ; {comment}")
                else:
                    assembly.append(disasm_line)
                
                # Move to next instruction
                address = instruction_iterator.next()
            
            # Join the disassembly lines
            assembly_str = "\n".join(assembly)
            
            return {"assembly": assembly_str, "function_name": func_name}
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_function_decompiled_by_name(self, function_name: str) -> Dict[str, Any]:
        """Get decompiled code for a function by its name"""
        try:
            # Get function address from name
            func_addr = idaapi.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # Call address-based implementation
            result = self.get_function_decompiled_by_address(func_addr)
            
            # If successful, add function name to result
            if "error" not in result:
                result["function_name"] = function_name
                
            return result
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_function_decompiled_by_address(self, address: int) -> Dict[str, Any]:
        """Get decompiled code for a function by its address"""
        try:
            # Get function from address
            func = idaapi.get_func(address)
            if not func:
                return {"error": f"No function found at address 0x{address:X}"}
            
            # Get function name
            func_name = idaapi.get_func_name(func.start_ea)
            
            # Try to import decompiler module
            try:
                import ida_hexrays
            except ImportError:
                return {"error": "Hex-Rays decompiler is not available"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Unable to initialize Hex-Rays decompiler"}
            
            # Get decompiled function
            cfunc = None
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
            except Exception as e:
                return {"error": f"Unable to decompile function: {str(e)}"}
            
            if not cfunc:
                return {"error": "Decompilation failed"}
            
            # Get pseudocode as string
            decompiled_code = str(cfunc)
            
            return {"decompiled_code": decompiled_code, "function_name": func_name}
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_current_function_assembly(self) -> Dict[str, Any]:
        """Get assembly code for the function at the current cursor position"""
        try:
            # Get current address
            curr_addr = idaapi.get_screen_ea()
            if curr_addr == idaapi.BADADDR:
                return {"error": "No valid cursor position"}
            
            # Use the address-based implementation
            return self.get_function_assembly_by_address(curr_addr)
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_current_function_decompiled(self) -> Dict[str, Any]:
        """Get decompiled code for the function at the current cursor position"""
        try:
            # Get current address
            curr_addr = idaapi.get_screen_ea()
            if curr_addr == idaapi.BADADDR:
                return {"error": "No valid cursor position"}
            
            # Use the address-based implementation
            return self.get_function_decompiled_by_address(curr_addr)
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}
    
    @idaread
    def get_global_variable_by_name(self, variable_name: str) -> Dict[str, Any]:
        """Get global variable information by its name"""
        try:
            # Get variable address
            var_addr: int = ida_name.get_name_ea(0, variable_name)
            if var_addr == idaapi.BADADDR:
                return {"error": f"Global variable '{variable_name}' not found"}
            
            # Call address-based implementation
            result = self.get_global_variable_by_address(var_addr)
            
            # If successful, add variable name to result
            if "error" not in result and "variable_info" in result:
                # Parse the JSON string back to dict to modify it
                var_info = json.loads(result["variable_info"])
                var_info["name"] = variable_name
                # Convert back to JSON string
                result["variable_info"] = json.dumps(var_info, indent=2)
                
            return result
        except Exception as e:
            print(f"Error getting global variable by name: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    @idaread
    def get_global_variable_by_address(self, address: int) -> Dict[str, Any]:
        """Get global variable information by its address"""
        try:
            # Verify address is valid
            if address == idaapi.BADADDR:
                return {"error": f"Invalid address: {hex(address)}"}
            
            # Get variable name if available
            variable_name = ida_name.get_name(address)
            if not variable_name:
                variable_name = f"unnamed_{hex(address)}"
            
            # Get variable segment
            segment: Optional[ida_segment.segment_t] = ida_segment.getseg(address)
            if not segment:
                return {"error": f"No segment found for address {hex(address)}"}
            
            segment_name: str = ida_segment.get_segm_name(segment)
            segment_class: str = ida_segment.get_segm_class(segment)
            
            # Get variable type
            tinfo = idaapi.tinfo_t()
            guess_type: bool = idaapi.guess_tinfo(tinfo, address)
            type_str: str = tinfo.get_type_name() if guess_type else "unknown"
            
            # Try to get variable value
            size: int = ida_bytes.get_item_size(address)
            if size <= 0:
                size = 8  # Default to 8 bytes
            
            # Read data based on size
            value: Optional[int] = None
            if size == 1:
                value = ida_bytes.get_byte(address)
            elif size == 2:
                value = ida_bytes.get_word(address)
            elif size == 4:
                value = ida_bytes.get_dword(address)
            elif size == 8:
                value = ida_bytes.get_qword(address)
            
            # Build variable info
            var_info: Dict[str, Any] = {
                "name": variable_name,
                "address": hex(address),
                "segment": segment_name,
                "segment_class": segment_class,
                "type": type_str,
                "size": size,
                "value": hex(value) if value is not None else "N/A"
            }
            
            # If it's a string, try to read string content
            if ida_bytes.is_strlit(ida_bytes.get_flags(address)):
                str_value = idc.get_strlit_contents(address, -1, 0)
                if str_value:
                    try:
                        var_info["string_value"] = str_value.decode('utf-8', errors='replace')
                    except:
                        var_info["string_value"] = str(str_value)
            
            return {"variable_info": json.dumps(var_info, indent=2)}
        except Exception as e:
            print(f"Error getting global variable by address: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    @idawrite
    def rename_global_variable(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a global variable"""
        try:
            # Get variable address
            var_addr: int = ida_name.get_name_ea(0, old_name)
            if var_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Variable '{old_name}' not found"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(var_addr, new_name):
                return {"success": False, "message": f"Failed to rename variable, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self.refresh_view_internal()
            
            return {"success": True, "message": f"Variable renamed from '{old_name}' to '{new_name}' at address {hex(var_addr)}"}
        
        except Exception as e:
            print(f"Error renaming variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def rename_function(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a function"""
        try:
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, old_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{old_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{old_name}' is not a function"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(func_addr, new_name):
                return {"success": False, "message": f"Failed to rename function, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self.refresh_view_internal()
            
            return {"success": True, "message": f"Function renamed from '{old_name}' to '{new_name}' at address {hex(func_addr)}"}
        
        except Exception as e:
            print(f"Error renaming function: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def add_assembly_comment(self, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add an assembly comment"""
        try:
            # Convert address string to integer
            addr: int
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    try:
                        addr = int(address, 16)  # Try parsing as hex
                    except ValueError:
                        try:
                            addr = int(address)  # Try parsing as decimal
                        except ValueError:
                            return {"success": False, "message": f"Invalid address format: {address}"}
            else:
                addr = address
            
            # Check if address is valid
            if addr == idaapi.BADADDR or not ida_bytes.is_loaded(addr):
                return {"success": False, "message": f"Invalid or unloaded address: {hex(addr)}"}
            
            # Add comment
            result: bool = idc.set_cmt(addr, comment, is_repeatable)
            if result:
                # Refresh view
                self.refresh_view_internal()
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} assembly comment at address {hex(addr)}"}
            else:
                return {"success": False, "message": f"Failed to add assembly comment at address {hex(addr)}"}
        
        except Exception as e:
            print(f"Error adding assembly comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def rename_local_variable(self, function_name: str, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a local variable within a function"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not old_name:
                return {"success": False, "message": "Old variable name cannot be empty"}
            if not new_name:
                return {"success": False, "message": "New variable name cannot be empty"}
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc: Optional[ida_hexrays.cfunc_t] = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Find local variable to rename
            found: bool = False
            renamed: bool = False
            lvar: Optional[ida_hexrays.lvar_t] = None
            
            # Iterate through all local variables
            lvars = cfunc.get_lvars()
            for i in range(lvars.size()):
                v = lvars[i]
                if v.name == old_name:
                    lvar = v
                    found = True
                    break
            
            if not found:
                return {"success": False, "message": f"Local variable '{old_name}' not found in function '{function_name}'"}
            
            # Rename local variable
            if ida_hexrays.rename_lvar(cfunc.entry_ea, lvar.name, new_name):
                renamed = True
            
            if renamed:
                # Refresh view
                self.refresh_view_internal()
                return {"success": True, "message": f"Local variable renamed from '{old_name}' to '{new_name}' in function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to rename local variable from '{old_name}' to '{new_name}', possibly due to invalid name format or other IDA restrictions"}
        
        except Exception as e:
            print(f"Error renaming local variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def add_function_comment(self, function_name: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add a comment to a function"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not comment:
                # Allow empty comment to clear the comment
                comment = ""
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Add function comment
            # is_repeatable=True means show comment at all references to this function
            # is_repeatable=False means show comment only at function definition
            result: bool = idc.set_func_cmt(func_addr, comment, is_repeatable)
            
            if result:
                # Refresh view
                self.refresh_view_internal()
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} comment to function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to add comment to function '{function_name}'"}
        
        except Exception as e:
            print(f"Error adding function comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def add_pseudocode_comment(self, function_name: str, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add a comment to a specific address in the function's decompiled pseudocode"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not address:
                return {"success": False, "message": "Address cannot be empty"}
            if not comment:
                # Allow empty comment to clear the comment
                comment = ""
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc: Optional[ida_hexrays.cfunc_t] = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Convert address string to integer
            addr: int
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    try:
                        addr = int(address, 16)  # Try parsing as hex
                    except ValueError:
                        try:
                            addr = int(address)  # Try parsing as decimal
                        except ValueError:
                            return {"success": False, "message": f"Invalid address format: {address}"}
            else:
                addr = address
                
            # Check if address is valid
            if addr == idaapi.BADADDR or not ida_bytes.is_loaded(addr):
                return {"success": False, "message": f"Invalid or unloaded address: {hex(addr)}"}
                
            # Check if address is within function
            if not (func.start_ea <= addr < func.end_ea):
                return {"success": False, "message": f"Address {hex(addr)} is not within function '{function_name}'"}
            
            # Create treeloc_t object for comment location
            loc = ida_hexrays.treeloc_t()
            loc.ea = addr
            loc.itp = ida_hexrays.ITP_BLOCK1  # Comment location
            
            # Set comment
            cfunc.set_user_cmt(loc, comment)
            cfunc.save_user_cmts()
            
            # Refresh view
            self.refresh_view_internal()
            
            comment_type: str = "repeatable" if is_repeatable else "regular"
            return {
                "success": True, 
                "message": f"Added {comment_type} comment at address {hex(addr)} in function '{function_name}'"
            }    
        
        except Exception as e:
            print(f"Error adding pseudocode comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def refresh_view(self) -> Dict[str, Any]:
        """Refresh IDA Pro view"""
        return self.refresh_view_internal()
    
    def refresh_view_internal(self) -> Dict[str, Any]:
        """Implementation of refreshing view in IDA main thread"""
        try:
            # Refresh disassembly view
            idaapi.refresh_idaview_anyway()
            
            # Refresh decompilation view
            current_widget = idaapi.get_current_widget()
            if current_widget:
                widget_type: int = idaapi.get_widget_type(current_widget)
                if widget_type == idaapi.BWN_PSEUDOCODE:
                    # If current view is pseudocode, refresh it
                    vu = idaapi.get_widget_vdui(current_widget)
                    if vu:
                        vu.refresh_view(True)
            
            # Try to find and refresh all open pseudocode windows
            for i in range(5):  # Check multiple possible pseudocode windows
                widget_name: str = f"Pseudocode-{chr(65+i)}"  # Pseudocode-A, Pseudocode-B, ...
                widget = idaapi.find_widget(widget_name)
                if widget:
                    vu = idaapi.get_widget_vdui(widget)
                    if vu:
                        vu.refresh_view(True)
            
            return {"success": True, "message": "Views refreshed successfully"}
        except Exception as e:
            print(f"Error refreshing views: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    @idawrite
    def execute_script(self, script: str) -> Dict[str, Any]:
        """Execute a Python script in IDA context"""
        try:
            print(f"Executing script, length: {len(script) if script else 0}")
            
            # Check for empty script
            if not script or not script.strip():
                print("Error: Empty script provided")
                return {
                    "success": False,
                    "error": "Empty script provided",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
                
            # Create a local namespace for script execution
            script_globals = {
                '__builtins__': __builtins__,
                'idaapi': idaapi,
                'idautils': idautils,
                'idc': idc,
                'ida_funcs': ida_funcs,
                'ida_bytes': ida_bytes,
                'ida_name': ida_name,
                'ida_segment': ida_segment,
                'ida_lines': ida_lines,
                'ida_hexrays': ida_hexrays
            }
            script_locals = {}

            # Save original stdin/stdout/stderr
            import sys
            import io
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            original_stdin = sys.stdin

            # Create string IO objects to capture output
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            # Redirect stdout/stderr to capture output
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            
            # Prevent script from trying to read from stdin
            sys.stdin = io.StringIO()

            try:
                # Create UI hooks 
                print("Setting up UI hooks")
                hooks = self._create_ui_hooks()
                hooks.hook()

                # Install auto-continue handlers for common dialogs - but first, redirect stderr
                temp_stderr = sys.stderr
                auto_handler_stderr = io.StringIO()
                sys.stderr = auto_handler_stderr
                
                print("Installing auto handlers")
                self._install_auto_handlers()
                
                # Restore stderr and save auto-handler errors separately
                sys.stderr = stderr_capture
                auto_handler_errors = auto_handler_stderr.getvalue()
                
                # Only log auto-handler errors, don't include in script output
                if auto_handler_errors:
                    print(f"Auto-handler setup errors (not shown to user): {auto_handler_errors}")

                # Execute the script
                print("Executing script...")
                exec(script, script_globals, script_locals)
                print("Script execution completed")
                
                # Get captured output
                stdout = stdout_capture.getvalue()
                stderr = stderr_capture.getvalue()
                
                # Filter out auto-handler messages from stdout
                stdout_lines = stdout.splitlines()
                filtered_stdout_lines = []
                
                for line in stdout_lines:
                    skip_line = False
                    auto_handler_messages = [
                        "Setting up UI hooks",
                        "Installing auto handlers",
                        "Error installing auto handlers",
                        "Found and saved",
                        "Could not access user_cancelled",
                        "Installed auto_",
                        "Auto handlers installed",
                        "Note: Could not",
                        "Restoring IO streams",
                        "Unhooking UI hooks",
                        "Restoring original handlers",
                        "Refreshing view",
                        "Original handlers restored",
                        "No original handlers"
                    ]
                    
                    for msg in auto_handler_messages:
                        if msg in line:
                            skip_line = True
                            break
                            
                    if not skip_line:
                        filtered_stdout_lines.append(line)
                
                filtered_stdout = "\n".join(filtered_stdout_lines)
                
                # Compile script results - ensure all fields are present
                result = {
                    "stdout": filtered_stdout.strip() if filtered_stdout else "",
                    "stderr": stderr.strip() if stderr else "",
                    "success": True,
                    "traceback": ""
                }
                
                # Check for return value
                if "result" in script_locals:
                    try:
                        print(f"Script returned value of type: {type(script_locals['result']).__name__}")
                        result["return_value"] = str(script_locals["result"])
                    except Exception as rv_err:
                        print(f"Error converting return value: {str(rv_err)}")
                        result["stderr"] += f"\nError converting return value: {str(rv_err)}"
                        result["return_value"] = "Error: Could not convert return value to string"
                
                print(f"Returning script result with keys: {', '.join(result.keys())}")
                return result
            except Exception as e:
                import traceback
                error_msg = str(e)
                tb = traceback.format_exc()
                print(f"Script execution error: {error_msg}")
                print(tb)
                return {
                    "success": False,
                    "stdout": stdout_capture.getvalue().strip() if stdout_capture else "",
                    "stderr": stderr_capture.getvalue().strip() if stderr_capture else "",
                    "error": error_msg,
                    "traceback": tb
                }
            finally:
                # Restore original stdin/stdout/stderr
                print("Restoring IO streams")
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                sys.stdin = original_stdin
                
                # Unhook UI hooks
                print("Unhooking UI hooks")
                hooks.unhook()
                
                # Restore original handlers
                print("Restoring original handlers")
                self._restore_original_handlers()
                
                # Refresh view to show any changes made by script
                print("Refreshing view")
                self.refresh_view_internal()
        except Exception as e:
            print(f"Error in execute_script outer scope: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    @idawrite
    def execute_script_from_file(self, file_path: str) -> Dict[str, Any]:
        """Execute a Python script from a file in IDA context"""
        try:
            # Check if file path is provided
            if not file_path or not file_path.strip():
                return {
                    "success": False,
                    "error": "No file path provided",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
                
            # Check if file exists
            import os
            if not os.path.exists(file_path):
                return {
                    "success": False,
                    "error": f"Script file not found: {file_path}",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
            
            try:
                # Read script content
                with open(file_path, 'r') as f:
                    script = f.read()
                
                # Execute script
                return self.execute_script(script)
            except Exception as file_error:
                print(f"Error reading or executing script file: {str(file_error)}")
                traceback.print_exc()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "",
                    "error": f"Error with script file: {str(file_error)}",
                    "traceback": traceback.format_exc()
                }
        except Exception as e:
            print(f"Error executing script from file: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    def _create_ui_hooks(self) -> idaapi.UI_Hooks:
        """Create UI hooks to suppress dialogs during script execution"""
        try:
            class DialogHook(idaapi.UI_Hooks):
                def populating_widget_popup(self, widget, popup):
                    # Just suppress all popups
                    return 1
                
                def finish_populating_widget_popup(self, widget, popup):
                    # Also suppress here
                    return 1
                
                def ready_to_run(self):
                    # Always continue
                    return 1
                
                def updating_actions(self, ctx):
                    # Always continue
                    return 1
                
                def updated_actions(self):
                    # Always continue
                    return 1
                
                def ui_refresh(self, cnd):
                    # Suppress UI refreshes
                    return 1
            
            hooks = DialogHook()
            return hooks
        except Exception as e:
            print(f"Error creating UI hooks: {str(e)}")
            traceback.print_exc()
            
            # Create minimal dummy hooks that won't cause errors
            class DummyHook:
                def hook(self):
                    print("Using dummy hook (hook)")
                    pass
                
                def unhook(self):
                    print("Using dummy hook (unhook)")
                    pass
            
            return DummyHook()

    def _install_auto_handlers(self) -> None:
        """Install auto-continue handlers for common dialogs"""
        try:
            import ida_kernwin
            
            # Save original handlers - with safer access to cvar.user_cancelled
            self._original_handlers = {}
            
            # Try to access user_cancelled more safely
            try:
                if hasattr(ida_kernwin, 'cvar') and hasattr(ida_kernwin.cvar, 'user_cancelled'):
                    self._original_handlers["yn"] = ida_kernwin.cvar.user_cancelled
                    print("Found and saved user_cancelled handler")
            except Exception as yn_err:
                print(f"Note: Could not access user_cancelled: {str(yn_err)}")
            
            # Save other dialog handlers
            if hasattr(ida_kernwin, 'ask_buttons'):
                self._original_handlers["buttons"] = ida_kernwin.ask_buttons
            
            if hasattr(ida_kernwin, 'ask_text'):
                self._original_handlers["text"] = ida_kernwin.ask_text
            
            if hasattr(ida_kernwin, 'ask_file'):
                self._original_handlers["file"] = ida_kernwin.ask_file
            
            # Define auto handlers
            def auto_yes_no(*args, **kwargs):
                return 1  # Return "Yes"
            
            def auto_buttons(*args, **kwargs):
                return 1  # Return first button
            
            def auto_text(*args, **kwargs):
                return ""  # Return empty text
            
            def auto_file(*args, **kwargs):
                return ""  # Return empty filename
            
            # Install auto handlers only for what we successfully saved
            if "yn" in self._original_handlers:
                try:
                    ida_kernwin.cvar.user_cancelled = auto_yes_no
                    print("Installed auto_yes_no handler")
                except Exception as e:
                    print(f"Could not install auto_yes_no handler: {str(e)}")
            
            if "buttons" in self._original_handlers:
                ida_kernwin.ask_buttons = auto_buttons
                print("Installed auto_buttons handler")
            
            if "text" in self._original_handlers:
                ida_kernwin.ask_text = auto_text
                print("Installed auto_text handler")
            
            if "file" in self._original_handlers:
                ida_kernwin.ask_file = auto_file
                print("Installed auto_file handler")
            
            print(f"Auto handlers installed successfully. Installed handlers: {', '.join(self._original_handlers.keys())}")
        except Exception as e:
            print(f"Error installing auto handlers: {str(e)}")
            traceback.print_exc()
            # Ensure _original_handlers exists even on failure
            if not hasattr(self, "_original_handlers"):
                self._original_handlers = {}

    def _restore_original_handlers(self) -> None:
        """Restore original dialog handlers"""
        try:
            if hasattr(self, "_original_handlers"):
                import ida_kernwin
                
                # Restore original handlers (only what was successfully saved)
                if "yn" in self._original_handlers:
                    try:
                        ida_kernwin.cvar.user_cancelled = self._original_handlers["yn"]
                        print("Restored user_cancelled handler")
                    except Exception as e:
                        print(f"Could not restore user_cancelled handler: {str(e)}")
                
                if "buttons" in self._original_handlers:
                    ida_kernwin.ask_buttons = self._original_handlers["buttons"]
                    print("Restored ask_buttons handler")
                
                if "text" in self._original_handlers:
                    ida_kernwin.ask_text = self._original_handlers["text"]
                    print("Restored ask_text handler")
                
                if "file" in self._original_handlers:
                    ida_kernwin.ask_file = self._original_handlers["file"]
                    print("Restored ask_file handler")
                
                saved_keys = list(self._original_handlers.keys())
                if saved_keys:
                    print(f"Original handlers restored: {', '.join(saved_keys)}")
                else:
                    print("No original handlers were saved, nothing to restore")
            else:
                print("No original handlers dictionary to restore")
        except Exception as e:
            print(f"Error restoring original handlers: {str(e)}")
            traceback.print_exc() 