#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Any, Optional
from .base_encrypt import BaseEncryptor
import os

class Rc4Encryptor(BaseEncryptor):
    def __init__(self, key: Optional[bytes] = None):
        # RC4 密钥长度可变，这里默认生成16字节密钥
        self.key = key if key is not None else os.urandom(16)
        self.key_len = len(self.key)
    
    @property
    def alg_name(self) -> str:
        return "RC4"
    
    @property
    def alg_full_name(self) -> str:
        return "RC4（流加密，高效轻便）"
    
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        # 初始化S盒
        s_box = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s_box[i] + self.key[i % self.key_len]) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
        
        # 加密过程
        i = j = 0
        encrypted_data = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + s_box[i]) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
            k = s_box[(s_box[i] + s_box[j]) % 256]
            encrypted_data.append(byte ^ k)
        
        return bytes(encrypted_data), {
            "key": self.key,
            "key_hex": self.key.hex(),
            "key_len": self.key_len
        }
