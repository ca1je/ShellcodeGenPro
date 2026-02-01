#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bin文件处理模块：单一职责 - 读取bin文件，生成原始bytes类型shellcode
"""
import os

class BinFileHandler:
    """Bin文件处理器：仅负责bin文件的读取和shellcode生成"""
    def load_bin_to_shellcode(self, bin_file_path: str) -> bytes:
        """
        从bin文件读取内容，生成原始shellcode
        :param bin_file_path: bin文件路径
        :return: 原始shellcode（bytes类型）
        """
        # 校验文件是否存在
        if not os.path.exists(bin_file_path):
            raise FileNotFoundError(f"bin文件不存在：{bin_file_path}")
        
        # 校验是否为有效文件
        if not os.path.isfile(bin_file_path):
            raise ValueError(f"输入路径不是有效文件：{bin_file_path}")
        
        # 读取二进制内容（核心职责）
        with open(bin_file_path, "rb") as f:
            shellcode = f.read()
        
        # 校验shellcode是否为空
        if not shellcode:
            raise ValueError("bin文件内容为空，无法生成有效shellcode")
        
        return shellcode