#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Any, Optional
from .base_encrypt import BaseEncryptor
import os

class XorEncryptor(BaseEncryptor):
    def __init__(self, key: Optional[bytes] = None):
        # 自定义密钥优先，否则随机生成4字节密钥
        self.key = key if key is not None else os.urandom(4)
        self.key_len = len(self.key)
    
    @property
    def alg_name(self) -> str:
        return "XOR"
    
    @property
    def alg_full_name(self) -> str:
        return "XOR（简单快速，基础免杀）"
    
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        encrypted_data = bytes([b ^ self.key[i % self.key_len] for i, b in enumerate(data)])
        return encrypted_data, {
            "key": self.key,
            "key_hex": self.key.hex(),
            "key_len": self.key_len
        }