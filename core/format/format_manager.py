#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式化管理器模块：单一职责 - 调度格式化工具、语言适配器，管理全语言格式化流程
"""
from typing import Optional
from .base_format import BaseFormatter
from .hex_format import HexEscapeFormatter
from .bytearray_format import ByteArrayFormatter
from .lang_adapter import LangAdapter
from . import OUTPUT_FORMATS, LANG_TYPES

class FormatManager:
    """格式化管理器：支持全语言格式化流程，生成直接可复用的代码"""
    def __init__(self):
        # 注册格式化工具
        self._formatters = [
            HexEscapeFormatter(),
            ByteArrayFormatter()
        ]
    
    def _get_formatter(self, output_format: str) -> BaseFormatter:
        """根据输出格式获取格式化工具实例"""
        fmt_flag = OUTPUT_FORMATS.get(output_format)
        if not fmt_flag:
            raise ValueError(f"不支持的输出格式：{output_format}")
        
        for formatter in self._formatters:
            if formatter.format_type == fmt_flag:
                return formatter
        raise ValueError(f"找不到对应的格式化工具：{output_format}")
    
    def format(
        self,
        shellcode: bytes,
        output_format: str,
        lang_type: str,
        group_size: Optional[int] = None
    ) -> str:
        """
        调度全语言格式化流程，生成直接可复用的目标语言代码
        :param shellcode: 待格式化shellcode
        :param output_format: 输出格式
        :param lang_type: 目标编程语言
        :param group_size: 分组大小
        :return: 直接可复用的目标语言代码
        """
        # 1. 获取格式化工具和目标语言标识
        formatter = self._get_formatter(output_format)
        fmt_flag = formatter.format_type
        target_lang = LANG_TYPES[lang_type]
        
        # 2. 生成基础格式化内容（传递目标语言，做语法适配）
        if group_size and group_size > 0:
            # 统一调用format_grouped方法，简化逻辑
            base_formatted = formatter.format_grouped(shellcode, group_size, target_lang)
        else:
            base_formatted = formatter.format_single(shellcode)
        
        # 3. 语言最终适配，生成直接可复用的代码
        lang_adapter = LangAdapter(target_lang)
        adapted_formatted = lang_adapter.adapt(base_formatted, fmt_flag, len(shellcode))
        
        return adapted_formatted