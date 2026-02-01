#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
字节数组格式格式化模块：单一职责 - 实现全语言字节数组格式的格式化，遵循BaseFormatter接口
"""
from typing import Optional
from .base_format import BaseFormatter

class ByteArrayFormatter(BaseFormatter):
    """字节数组格式格式化器：支持全语言字节数组分组适配，符合各语言语法特性"""
    @property
    def format_type(self) -> str:
        return "byte_array"
    
    def format_single(self, shellcode: bytes) -> str:
        """格式化单个字节数组字符串（不分组）"""
        if not shellcode:
            raise ValueError("待格式化shellcode不能为空")
        return ', '.join([f"0x{b:02x}" for b in shellcode])
    
    def format_grouped(self, shellcode: bytes, group_size: int = 16, lang_type: str = None) -> str:
        """
        格式化分组字节数组字符串（适配全语言语法特性，无冗余逗号，便于直接复用）
        :param shellcode: 待格式化shellcode
        :param group_size: 每组字节数
        :param lang_type: 目标语言（c/python/ruby/go）
        :return: 分组后的符合目标语言语法的字符串
        """
        if group_size <= 0:
            raise ValueError("分组大小必须大于0")
        
        # 步骤1：生成单个字节对应的0x字符串列表
        byte_list = [f"0x{b:02x}" for b in shellcode]
        grouped_lines = []
        
        # 步骤2：按group_size切分列表
        for i in range(0, len(byte_list), group_size):
            current_group = byte_list[i:i+group_size]
            grouped_lines.append(', '.join(current_group))
        
        # 步骤3：按目标语言做特殊语法适配（处理冗余逗号，符合语法规范）
        lang = lang_type.lower() if lang_type else "unknown"
        full_content = ',\n'.join(grouped_lines)
        
        # 各语言统一：整体无冗余末尾逗号，仅内部分组换行分隔
        if lang in ["c", "python", "ruby", "go", "csharp", "java"]:
            return full_content
        else:
            # 默认：末尾加逗号（兼容旧语法）
            return full_content + ','