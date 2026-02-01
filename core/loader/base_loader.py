#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加载器基类模块：单一职责 - 定义所有加载器的统一接口，便于扩展
"""
from abc import ABC, abstractmethod
from core.encrypt.encrypt_manager import EncryptionHistory

class BaseLoader(ABC):
    """加载器基类：定义统一加载器生成接口，所有加载器必须实现该接口"""
    @property
    @abstractmethod
    def lang_name(self) -> str:
        """返回目标编程语言名称"""
        pass
    
    @abstractmethod
    def generate_raw(self, shellcode_len: int) -> str:
        """生成原始加载器（无解密）"""
        pass
    
    @abstractmethod
    def generate_decrypt(self, shellcode_len: int, encryption_history: EncryptionHistory) -> str:
        """生成解密加载器（适配加密历史）"""
        pass