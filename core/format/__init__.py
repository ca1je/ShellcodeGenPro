#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 支持的输出格式和语言（模块化导出）
OUTPUT_FORMATS = {
    "\\x格式（如：\\x00\\x01）": "hex_escape",
    "字节数组格式（如：0x00, 0x01）": "byte_array"
}

LANG_TYPES = {
    "C/C++": "c",
    "Python": "python",
    "Ruby": "ruby",
    "Go": "go",
    "C#": "csharp",
    "Java": "java"
}

from .format_manager import FormatManager