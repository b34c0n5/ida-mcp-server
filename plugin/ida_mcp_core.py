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

class IDASyncWrapper(object):
    """Wrapper class for getting return value from execute_sync"""
    def __init__(self):
        self.result = None

    def __call__(self, func, *args, **kwargs):
        self.result = func(*args, **kwargs)
        return 1

class IDAMCPCore:
    """Core functionality implementation class for IDA MCP"""
    
    def __init__(self):
        self.wrapper = IDASyncWrapper()
    
    def execute_sync(self, func, *args, **kwargs):
        """Execute function synchronously in IDA main thread"""
        idaapi.execute_sync(lambda: self.wrapper(func, *args, **kwargs), idaapi.MFF_READ)
        return self.wrapper.result
    
    def execute_sync_write(self, func, *args, **kwargs):
        """Execute write operation function synchronously in IDA main thread"""
        idaapi.execute_sync(lambda: self.wrapper(func, *args, **kwargs), idaapi.MFF_WRITE)
        return self.wrapper.result
    
    def get_function_assembly(self, function_name):
        """Get assembly code for a function"""
        return self.execute_sync(self._get_function_assembly_impl, function_name)
    
    def _get_function_assembly_impl(self, function_name):
        """Implementation of getting function assembly in IDA main thread"""
        try:
            # Get function address
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # Get function object
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}
            
            # Collect all assembly instructions
            assembly_lines = []
            for instr_addr in idautils.FuncItems(func_addr):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")
            
            if not assembly_lines:
                return {"error": "No assembly instructions found"}
                
            return {"assembly": "\n".join(assembly_lines)}
        except Exception as e:
            print(f"Error getting function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_function_decompiled(self, function_name):
        """Get decompiled pseudocode for a function"""
        return self.execute_sync(self._get_function_decompiled_impl, function_name)
    
    def _get_function_decompiled_impl(self, function_name):
        """Implementation of getting function decompiled code in IDA main thread"""
        try:
            # Get function address
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # Get function object
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"error": f"Invalid function at {hex(func_addr)}"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}
            
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Get decompilation result
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"error": "Failed to decompile function"}
            
            # Get pseudocode text
            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}
                
            decompiled_text = []
            
            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:  # Ensure not None
                    decompiled_text.append(line_text)
            
            # Ensure string return
            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}
                
            result = "\n".join(decompiled_text)
            
            # Debug output
            print(f"Decompiled text type: {type(result).__name__}, length: {len(result)}")
            
            return {"decompiled_code": result}
        except Exception as e:
            print(f"Error decompiling function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_global_variable(self, variable_name):
        """Get global variable information"""
        return self.execute_sync(self._get_global_variable_impl, variable_name)
    
    def _get_global_variable_impl(self, variable_name):
        """Implementation of getting global variable in IDA main thread"""
        try:
            # Get variable address
            var_addr = ida_name.get_name_ea(0, variable_name)
            if var_addr == idaapi.BADADDR:
                return {"error": f"Global variable '{variable_name}' not found"}
            
            # Get variable segment
            segment = ida_segment.getseg(var_addr)
            if not segment:
                return {"error": f"No segment found for address {hex(var_addr)}"}
            
            segment_name = ida_segment.get_segm_name(segment)
            segment_class = ida_segment.get_segm_class(segment)
            
            # Get variable type
            tinfo = idaapi.tinfo_t()
            guess_type = idaapi.guess_tinfo(tinfo, var_addr)
            type_str = tinfo.get_type_name() if guess_type else "unknown"
            
            # Try to get variable value
            size = ida_bytes.get_item_size(var_addr)
            if size <= 0:
                size = 8  # Default to 8 bytes
            
            # Read data based on size
            value = None
            if size == 1:
                value = ida_bytes.get_byte(var_addr)
            elif size == 2:
                value = ida_bytes.get_word(var_addr)
            elif size == 4:
                value = ida_bytes.get_dword(var_addr)
            elif size == 8:
                value = ida_bytes.get_qword(var_addr)
            
            # Build variable info
            var_info = {
                "name": variable_name,
                "address": hex(var_addr),
                "segment": segment_name,
                "segment_class": segment_class,
                "type": type_str,
                "size": size,
                "value": hex(value) if value is not None else "N/A"
            }
            
            # If it's a string, try to read string content
            if ida_bytes.is_strlit(ida_bytes.get_flags(var_addr)):
                str_value = idc.get_strlit_contents(var_addr, -1, 0)
                if str_value:
                    try:
                        var_info["string_value"] = str_value.decode('utf-8', errors='replace')
                    except:
                        var_info["string_value"] = str(str_value)
            
            return {"variable_info": json.dumps(var_info, indent=2)}
        except Exception as e:
            print(f"Error getting global variable: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_current_function_assembly(self):
        """Get assembly code for the function at current cursor position"""
        return self.execute_sync(self._get_current_function_assembly_impl)
    
    def _get_current_function_assembly_impl(self):
        """Implementation of getting current function assembly in IDA main thread"""
        try:
            # Get current cursor address
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}
            
            # Get function object
            func = ida_funcs.get_func(current_addr)
            if not func:
                return {"error": f"No function found at current position {hex(current_addr)}"}
            
            # Get function name
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # Collect all assembly instructions
            assembly_lines = []
            for instr_addr in idautils.FuncItems(func.start_ea):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")
            
            if not assembly_lines:
                return {"error": "No assembly instructions found"}
                
            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "assembly": "\n".join(assembly_lines)
            }
        except Exception as e:
            print(f"Error getting current function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def get_current_function_decompiled(self):
        """Get decompiled code for the function at current cursor position"""
        return self.execute_sync(self._get_current_function_decompiled_impl)
    
    def _get_current_function_decompiled_impl(self):
        """Implementation of getting current function decompiled code in IDA main thread"""
        try:
            # Get current cursor address
            current_addr = idaapi.get_screen_ea()
            if current_addr == idaapi.BADADDR:
                return {"error": "Invalid cursor position"}
            
            # Get function object
            func = ida_funcs.get_func(current_addr)
            if not func:
                return {"error": f"No function found at current position {hex(current_addr)}"}
            
            # Get function name
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Hex-Rays decompiler not available"}
            
            # Get decompilation result
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": "Failed to decompile function"}
            
            # Get pseudocode text
            sv = cfunc.get_pseudocode()
            if not sv:
                return {"error": "No pseudocode generated"}
                
            decompiled_text = []
            
            for sline in sv:
                line_text = ida_lines.tag_remove(sline.line)
                if line_text is not None:  # Ensure not None
                    decompiled_text.append(line_text)
            
            # Ensure string return
            if not decompiled_text:
                return {"decompiled_code": "// No code content available"}
                
            result = "\n".join(decompiled_text)
            
            # Debug output
            print(f"Current function decompiled text type: {type(result).__name__}, length: {len(result)}")
            
            return {
                "function_name": func_name,
                "function_address": hex(func.start_ea),
                "decompiled_code": result
            }
        except Exception as e:
            print(f"Error decompiling current function: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    def rename_global_variable(self, old_name, new_name):
        """Rename a global variable"""
        return self.execute_sync_write(self._rename_global_variable_impl, old_name, new_name)
    
    def _rename_global_variable_impl(self, old_name, new_name):
        """Implementation of renaming global variable in IDA main thread"""
        try:
            # Get variable address
            var_addr = ida_name.get_name_ea(0, old_name)
            if var_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Variable '{old_name}' not found"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(var_addr, new_name):
                return {"success": False, "message": f"Failed to rename variable, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self._refresh_view_impl()
            
            return {"success": True, "message": f"Variable renamed from '{old_name}' to '{new_name}' at address {hex(var_addr)}"}
        
        except Exception as e:
            print(f"Error renaming variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def rename_function(self, old_name, new_name):
        """Rename a function"""
        return self.execute_sync_write(self._rename_function_impl, old_name, new_name)
    
    def _rename_function_impl(self, old_name, new_name):
        """Implementation of renaming function in IDA main thread"""
        try:
            # Get function address
            func_addr = ida_name.get_name_ea(0, old_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{old_name}' not found"}
            
            # Check if it's a function
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{old_name}' is not a function"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(func_addr, new_name):
                return {"success": False, "message": f"Failed to rename function, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self._refresh_view_impl()
            
            return {"success": True, "message": f"Function renamed from '{old_name}' to '{new_name}' at address {hex(func_addr)}"}
        
        except Exception as e:
            print(f"Error renaming function: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def add_assembly_comment(self, address, comment, is_repeatable):
        """Add an assembly comment"""
        return self.execute_sync_write(self._add_assembly_comment_impl, address, comment, is_repeatable)
    
    def _add_assembly_comment_impl(self, address, comment, is_repeatable):
        """Implementation of adding assembly comment in IDA main thread"""
        try:
            # Convert address string to integer
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
            result = idc.set_cmt(addr, comment, is_repeatable)
            if result:
                # Refresh view
                self._refresh_view_impl()
                comment_type = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} assembly comment at address {hex(addr)}"}
            else:
                return {"success": False, "message": f"Failed to add assembly comment at address {hex(addr)}"}
        
        except Exception as e:
            print(f"Error adding assembly comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def rename_local_variable(self, function_name, old_name, new_name):
        """Rename a local variable within a function"""
        return self.execute_sync_write(self._rename_local_variable_impl, function_name, old_name, new_name)
    
    def _rename_local_variable_impl(self, function_name, old_name, new_name):
        """Implementation of renaming local variable in IDA main thread"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not old_name:
                return {"success": False, "message": "Old variable name cannot be empty"}
            if not new_name:
                return {"success": False, "message": "New variable name cannot be empty"}
            
            # Get function address
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Find local variable to rename
            found = False
            renamed = False
            lvar = None
            
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
                self._refresh_view_impl()
                return {"success": True, "message": f"Local variable renamed from '{old_name}' to '{new_name}' in function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to rename local variable from '{old_name}' to '{new_name}', possibly due to invalid name format or other IDA restrictions"}
        
        except Exception as e:
            print(f"Error renaming local variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def add_function_comment(self, function_name, comment, is_repeatable):
        """Add a comment to a function"""
        return self.execute_sync_write(self._add_function_comment_impl, function_name, comment, is_repeatable)
    
    def _add_function_comment_impl(self, function_name, comment, is_repeatable):
        """Implementation of adding function comment in IDA main thread"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not comment:
                # Allow empty comment to clear the comment
                comment = ""
            
            # Get function address
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Add function comment
            # is_repeatable=True means show comment at all references to this function
            # is_repeatable=False means show comment only at function definition
            result = idc.set_func_cmt(func_addr, comment, is_repeatable)
            
            if result:
                # Refresh view
                self._refresh_view_impl()
                comment_type = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} comment to function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to add comment to function '{function_name}'"}
        
        except Exception as e:
            print(f"Error adding function comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def add_pseudocode_comment(self, function_name, address, comment, is_repeatable):
        """Add a comment to a specific address in the function's decompiled pseudocode"""
        return self.execute_sync_write(self._add_pseudocode_comment_impl, function_name, address, comment, is_repeatable)
    
    def _add_pseudocode_comment_impl(self, function_name, address, comment, is_repeatable):
        """Implementation of adding pseudocode comment in IDA main thread"""
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
            func_addr = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Convert address string to integer
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
            self._refresh_view_impl()
            
            comment_type = "repeatable" if is_repeatable else "regular"
            return {
                "success": True, 
                "message": f"Added {comment_type} comment at address {hex(addr)} in function '{function_name}'"
            }    
        
        except Exception as e:
            print(f"Error adding pseudocode comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    def refresh_view(self):
        """Refresh IDA Pro view"""
        return self.execute_sync_write(self._refresh_view_impl)
    
    def _refresh_view_impl(self):
        """Implementation of refreshing view in IDA main thread"""
        try:
            # Refresh disassembly view
            idaapi.refresh_idaview_anyway()
            
            # Refresh decompilation view
            current_widget = idaapi.get_current_widget()
            if current_widget:
                widget_type = idaapi.get_widget_type(current_widget)
                if widget_type == idaapi.BWN_PSEUDOCODE:
                    # If current view is pseudocode, refresh it
                    vu = idaapi.get_widget_vdui(current_widget)
                    if vu:
                        vu.refresh_view(True)
            
            # Try to find and refresh all open pseudocode windows
            for i in range(5):  # Check multiple possible pseudocode windows
                widget_name = f"Pseudocode-{chr(65+i)}"  # Pseudocode-A, Pseudocode-B, ...
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