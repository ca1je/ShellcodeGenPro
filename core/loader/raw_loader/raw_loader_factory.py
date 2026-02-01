#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
原始加载器工厂模块：单一职责 - 调度不同语言的原始加载器生成，不实现具体加载器逻辑
"""
from .c_raw_loader import CRawLoader
from .python_raw_loader import PythonRawLoader
from .ruby_raw_loader import RubyRawLoader
from .go_raw_loader import GoRawLoader
from .csharp_raw_loader import CSharpRawLoader
from .java_raw_loader import JavaRawLoader
from core.loader import LOADER_LANGS

class RawLoaderFactory:
    """原始加载器工厂：单一职责 - 创建对应语言的原始加载器实例"""
    def __init__(self):
        self._loader_map = {
            "C/C++": CRawLoader(),
            "Python": PythonRawLoader(),
            "Ruby": RubyRawLoader(),
            "Go": GoRawLoader(),
            "C#": CSharpRawLoader(),
            "Java": JavaRawLoader()
        }
    
    def create_loader(self, lang: str, shellcode_len: int) -> str:
        """创建对应语言的原始加载器"""
        if lang not in LOADER_LANGS:
            raise ValueError(f"不支持的加载器语言：{lang}")
        
        loader = self._loader_map.get(lang)
        if not loader:
            raise ValueError(f"找不到对应的原始加载器：{lang}")
        
        return loader.generate_raw(shellcode_len)