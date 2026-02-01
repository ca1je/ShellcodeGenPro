#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Any, Optional
from .base_encrypt import BaseEncryptor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class ChaCha20Encryptor2(BaseEncryptor):
    """ChaCha20加密器（Python版本）：生成12字节nonce以兼容pycryptodome库"""
    def __init__(self, key: Optional[bytes] = None, nonce: Optional[bytes] = None):
        # ChaCha20 密钥必须32字节，nonce必须12字节（pycryptodome库要求）
        self.key = key if key is not None else os.urandom(32)
        self.nonce = nonce if nonce is not None else os.urandom(12)
        if len(self.key) != 32:
            raise ValueError("ChaCha20 密钥必须为32字节")
        if len(self.nonce) != 12:
            raise ValueError("ChaCha20 nonce必须为12字节")
    
    @property
    def alg_name(self) -> str:
        return "ChaCha20"
    
    @property
    def alg_full_name(self) -> str:
        return "ChaCha20（现代流加密，高效安全）"
    
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        # 创建ChaCha20加密器
        cipher = Cipher(
            algorithms.ChaCha20(self.key, self.nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return encrypted_data, {
            "key": self.key,
            "key_hex": self.key.hex(),
            "nonce": self.nonce,
            "nonce_hex": self.nonce.hex()
        }
