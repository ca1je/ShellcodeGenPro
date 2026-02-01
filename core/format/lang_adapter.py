#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
语言适配模块：单一职责 - 实现全语言格式化内容最终适配，生成直接可复用的代码
"""
from typing import Optional

class LangAdapter:
    """语言适配器：支持全语言语法适配，生成无瑕疵可直接复用的代码"""
    def __init__(self, lang_type: str):
        self._lang_type = lang_type.lower()
        self._supported_langs = ["c", "python", "ruby", "go", "csharp", "java"]
        
        if self._lang_type not in self._supported_langs:
            raise ValueError(f"不支持的编程语言：{lang_type}，支持：{self._supported_langs}")
    
    def adapt(self, base_formatted: str, format_type: str, shellcode_len: int) -> str:
        """
        将基础格式化内容适配为对应编程语言的最终可复用代码
        :param base_formatted: 基础格式化内容
        :param format_type: 格式化类型（hex_escape/byte_array）
        :param shellcode_len: shellcode长度
        :return: 直接可复用的目标语言代码
        """
        if format_type == "hex_escape":
            return self._adapt_hex_escape(base_formatted, shellcode_len)
        elif format_type == "byte_array":
            return self._adapt_byte_array(base_formatted, shellcode_len)
        else:
            raise ValueError(f"不支持的格式化类型：{format_type}")
    
    def _adapt_hex_escape(self, base_formatted: str, shellcode_len: int) -> str:
        """适配\\x格式到对应语言，生成直接可复用的代码"""
        if self._lang_type == "c":
            # C/C++：unsigned类型 + 分行"" + 编译器自动拼接
            return f'unsigned char shellcode[] = "{base_formatted}";\nunsigned int shellcode_len = sizeof(shellcode)-1;'
        elif self._lang_type == "python":
            # Python：字节串b"" + ()自动拼接 + 直接赋值
            return f'shellcode = bytearray(\n    b"{base_formatted}"\n)\nshellcode_len = {shellcode_len}'
        elif self._lang_type == "ruby":
            # Ruby：字符串"" + +号拼接 + 直接赋值
            return f'shellcode = "{base_formatted}"\nshellcode_len = {shellcode_len}'
        elif self._lang_type == "go":
            # Go：[]byte("") + 分行"" + 编译器自动拼接 + 驼峰命名
            return f'shellcode := []byte("{base_formatted}")\nshellcodeLen := {shellcode_len}'
        elif self._lang_type == "csharp":
            # C#：字符串 + +号拼接 + 转换为字节数组
            return f'string shellcodeHex = "{base_formatted}";\nint shellcodeLen = {shellcode_len};\n// 转换为字节数组\nbyte[] shellcode = System.Convert.FromHexString(shellcodeHex.Replace("\\x", ""));'
        elif self._lang_type == "java":
            # Java：字符串 + +号拼接 + 转换为字节数组
            return f'String shellcodeHex = "{base_formatted}";\nint shellcodeLen = {shellcode_len};\n// 转换为字节数组\nbyte[] shellcode = javax.xml.bind.DatatypeConverter.parseHexBinary(shellcodeHex.replace("\\x", ""));'
    
    def _adapt_byte_array(self, base_formatted: str, shellcode_len: int) -> str:
        """适配字节数组格式到对应语言，生成直接可复用的代码"""
        if self._lang_type == "c":
            # C/C++：unsigned类型 + 大括号 + 无冗余逗号
            return f'unsigned char shellcode[] = {{\n{base_formatted}\n}};\nunsigned int shellcode_len = sizeof(shellcode);'
        elif self._lang_type == "python":
            # Python：bytearray()直接初始化 + 无冗余逗号
            return f'shellcode = bytearray([\n{base_formatted}\n])\nshellcode_len = {shellcode_len}'
        elif self._lang_type == "ruby":
            # Ruby：数组直接初始化 + 无冗余逗号
            return f'shellcode = [\n{base_formatted}\n]\nshellcode_len = {shellcode_len}'
        elif self._lang_type == "go":
            # Go：[]byte{}切片初始化 + 无冗余逗号 + 驼峰命名
            return f'shellcode := []byte{{\n{base_formatted}\n}}\nshellcodeLen := {shellcode_len}'
        elif self._lang_type == "csharp":
            # C#：byte[]数组初始化 + 无冗余逗号
            return f'byte[] shellcode = new byte[] {{\n{base_formatted}\n}};\nint shellcodeLen = {shellcode_len};'
        elif self._lang_type == "java":
            # Java：byte[]数组初始化 + 无冗余逗号
            return f'byte[] shellcode = new byte[] {{\n{base_formatted}\n}};\nint shellcodeLen = {shellcode_len};'