# import idapro
import traceback
import idaapi
import idautils
import idc
import ida_funcs
import idaapi
import ida_name
import ida_hexrays
import ida_funcs
import idautils
import sys
sys.path.append('..')
from plugin.ida_mcp_core import IDAMCPCore
# idapro.open_database("/Volumes/FrameworkLab/Dyld-Shared-Cache/macOS/15.1/dyld_shared_cache_arm64e-LaunchServices.i64", True)  # 替换为你的数据库路径

core = IDAMCPCore()
print(core.get_global_variable("dword_180981000"))
# idapro.close_database()