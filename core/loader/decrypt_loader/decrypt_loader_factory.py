#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解密加载器工厂模块：单一职责 - 调度不同语言的解密加载器生成，不实现具体加载器逻辑
"""
from .c_decrypt_loader import CDecryptLoader
from .python_decrypt_loader import PythonDecryptLoader
from .ruby_decrypt_loader import RubyDecryptLoader
from .go_decrypt_loader import GoDecryptLoader
from .csharp_decrypt_loader import CSharpDecryptLoader
from .java_decrypt_loader import JavaDecryptLoader
from core.loader import LOADER_LANGS
from core.encrypt.encrypt_manager import EncryptionHistory

class DecryptLoaderFactory:
    """解密加载器工厂：单一职责 - 创建对应语言的解密加载器实例"""
    def __init__(self):
        self._loader_map = {
            "C/C++": CDecryptLoader(),
            "Python": PythonDecryptLoader(),
            "Ruby": RubyDecryptLoader(),
            "Go": GoDecryptLoader(),
            "C#": CSharpDecryptLoader(),
            "Java": JavaDecryptLoader()
        }
    
    def create_loader(self, lang_name: str, shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """创建对应语言的解密加载器"""
        if lang_name not in LOADER_LANGS:
            raise ValueError(f"不支持的加载器语言：{lang_name}")
        if encryption_history.is_empty():
            raise ValueError("加密历史为空，无法生成解密加载器")
        
        loader = self._loader_map.get(lang_name)
        if not loader:
            raise ValueError(f"找不到对应的解密加载器：{lang_name}")
        
        return loader.generate_decrypt(shellcode_len, encryption_history)