#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Any, Optional
from .base_encrypt import BaseEncryptor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class Aes256CbcEncryptor(BaseEncryptor):
    def __init__(self, key: Optional[bytes] = None, iv: Optional[bytes] = None):
        # AES-256 密钥必须32字节，IV必须16字节
        self.key = key if key is not None else os.urandom(32)
        self.iv = iv if iv is not None else os.urandom(16)
        if len(self.key) != 32:
            raise ValueError("AES-256-CBC 密钥必须为32字节")
        if len(self.iv) != 16:
            raise ValueError("AES-256-CBC IV必须为16字节")
    
    @property
    def alg_name(self) -> str:
        return "AES-256-CBC"
    
    @property
    def alg_full_name(self) -> str:
        return "AES-256-CBC（高强度，推荐）"
    
    def encrypt(self, data: bytes) -> (bytes, Dict[str, Any]):
        # 使用PKCS7填充确保数据长度是块大小的倍数
        padder = padding.PKCS7(128).padder()  # AES块大小为128位(16字节)
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, {
            "key": self.key,
            "key_hex": self.key.hex(),
            "iv": self.iv,
            "iv_hex": self.iv.hex(),
            "block_size": 16,  # AES固定块大小为16字节
            "original_len": len(data),
            "encrypted_len": len(encrypted_data)
        }

