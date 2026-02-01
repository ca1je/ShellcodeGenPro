#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Any, Optional
from .base_encrypt import BaseEncryptor
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import os

class DesCbcEncryptor(BaseEncryptor):
    def __init__(self, key: Optional[bytes] = None, iv: Optional[bytes] = None):
        # DES 密钥必须8字节，IV必须8字节
        self.key = key if key is not None else os.urandom(8)
        self.iv = iv if iv is not None else os.urandom(8)
        if len(self.key) != 8:
            raise ValueError("DES-CBC 密钥必须为8字节")
        if len(self.iv) != 8:
            raise ValueError("DES-CBC IV必须为8字节")
    
    @property
    def alg_name(self) -> str:
        return "DES-CBC"
    
    @property
    def alg_full_name(self) -> str:
        return "DES-CBC（经典算法，兼容性好）"
    
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        # 只有当数据长度不是块大小的倍数时才添加PKCS7填充
        if len(data) % DES.block_size != 0:
            padded_data = pad(data, DES.block_size, style='pkcs7')
        else:
            padded_data = data
        cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data, {
            "key": self.key,
            "key_hex": self.key.hex(),
            "iv": self.iv,
            "iv_hex": self.iv.hex(),
            "block_size": DES.block_size,
            "original_len": len(data),
            "encrypted_len": len(encrypted_data)
        }

