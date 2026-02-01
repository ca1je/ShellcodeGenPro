#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseEncryptor(ABC):
    @property
    @abstractmethod
    def alg_name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def alg_full_name(self) -> str:
        pass
    
    @abstractmethod
    def __init__(self, key: Optional[bytes] = None, iv: Optional[bytes] = None):
        """
        初始化加密器
        :param key: 自定义密钥（None 则随机生成）
        :param iv: 自定义IV（仅对称加密需要，None 则随机生成）
        """
        pass
    
    @abstractmethod
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        pass