#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式化基类模块：单一职责 - 定义所有格式化工具的统一接口，便于扩展
"""
from abc import ABC, abstractmethod
from typing import Optional

class BaseFormatter(ABC):
    """格式化工具基类：定义统一格式化接口，所有格式化工具必须实现该接口"""
    @property
    @abstractmethod
    def format_type(self) -> str:
        """返回格式化类型（如：hex_escape、byte_array）"""
        pass
    
    @abstractmethod
    def format_single(self, shellcode: bytes) -> str:
        """格式化单个字符串（不分组）"""
        pass
    
    @abstractmethod
    def format_grouped(self, shellcode: bytes, group_size: int) -> str:
        """格式化分组字符串（便于阅读）"""
        pass