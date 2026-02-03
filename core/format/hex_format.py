#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
\\x格式格式化模块：单一职责 - 实现全语言\\x格式的格式化，遵循BaseFormatter接口
"""
from typing import Optional
from .base_format import BaseFormatter

class HexEscapeFormatter(BaseFormatter):
    """\\x格式格式化器：支持全语言\\x格式分组适配，符合各语言语法特性"""
    @property
    def format_type(self) -> str:
        return "hex_escape"
    
    def format_single(self, shellcode: bytes) -> str:
        """格式化单个\\x字符串（不分组）"""
        if not shellcode:
            raise ValueError("待格式化shellcode不能为空")
        return ''.join([f"\\x{b:02x}" for b in shellcode])
    
    def format_grouped(self, shellcode: bytes, group_size: int = 16, lang_type: str = None) -> str:
        """
        格式化分组\\x字符串（适配全语言语法特性，便于直接复用）
        :param shellcode: 待格式化shellcode
        :param group_size: 每组字节数
        :param lang_type: 目标语言（c/python/ruby/go）
        :return: 分组后的符合目标语言语法的字符串
        """
        if group_size <= 0:
            raise ValueError("分组大小必须大于0")
        
        # 步骤1：生成单个字节对应的\\x字符串列表
        hex_byte_list = [f"\\x{b:02x}" for b in shellcode]
        grouped_lines = []
        
        # 步骤2：按group_size切分列表
        for i in range(0, len(hex_byte_list), group_size):
            current_group = hex_byte_list[i:i+group_size]
            grouped_lines.append(''.join(current_group))
        
        # 步骤3：按目标语言做特殊语法适配
        lang = lang_type.lower() if lang_type else "unknown"
        if lang == "c":
            # C/C++：每行""包裹，编译器自动拼接（无+号，更简洁）
            return '"\n"'.join(grouped_lines)
        elif lang == "python":
            # Python：用()包裹，自动拼接字节串（无需+号，符合Python规范）
            return '"\n    b"'.join(grouped_lines)
        elif lang == "ruby":
            # Ruby：每行""包裹，用+号拼接（Ruby不支持直接相邻字符串自动拼接）
            return '"\n+ "'.join(grouped_lines)
        elif lang == "go":
            # Go：每行""包裹，编译器自动拼接（和C语言类似，符合Go规范）
            return '"+\n"'.join(grouped_lines)
        elif lang == "csharp":
            # C#：每行""包裹，用+号拼接（C#不支持直接相邻字符串自动拼接）
            return '"\n+ "'.join(grouped_lines)
        elif lang == "java":
            # Java：每行""包裹，编译器自动拼接（和C语言类似，符合Java规范）
            return '"\n"'.join(grouped_lines)
        else:
            # 默认：直接换行拼接
            return '\n'.join(grouped_lines)
