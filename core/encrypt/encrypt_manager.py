#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Dict, Any, Optional
from .base_encrypt import BaseEncryptor
from .xor_encrypt import XorEncryptor
from .aes_encrypt import Aes256CbcEncryptor
from .des_encrypt import DesCbcEncryptor
from .rc4_encrypt import Rc4Encryptor
from .chacha20_encrypt import ChaCha20Encryptor

class EncryptionHistory:
    def __init__(self):
        self._history: List[Dict[str, Any]] = []
    
    def add_encrypt_info(self, encrypt_info: Dict[str, Any]) -> None:
        if not isinstance(encrypt_info, dict) or "alg" not in encrypt_info:
            raise ValueError("无效的加密信息，无法添加到历史记录")
        self._history.append(encrypt_info)
    
    def get_full_history(self) -> List[Dict[str, Any]]:
        return self._history.copy()
    
    def is_empty(self) -> bool:
        return len(self._history) == 0

class EncryptManager:
    def __init__(self):
        self._encryptors: List[BaseEncryptor] = [
            XorEncryptor(),
            Aes256CbcEncryptor(),
            DesCbcEncryptor(),
            Rc4Encryptor(),
            ChaCha20Encryptor()
        ]
    
    @property
    def supported_algorithms(self) -> List[str]:
        return [encryptor.alg_full_name for encryptor in self._encryptors]
    
    def get_encryptor(self, alg_full_name: str, key: Optional[bytes] = None, iv: Optional[bytes] = None, nonce: Optional[bytes] = None, target_lang: str = "C/C++") -> BaseEncryptor:
        """
        获取加密器实例，支持传入自定义密钥/IV/nonce（根据算法类型传递对应参数）
        :param alg_full_name: 完整算法名称
        :param key: 自定义密钥
        :param iv: 自定义IV（仅AES/DES需要）
        :param nonce: 自定义nonce（仅ChaCha20需要）
        :param target_lang: 目标语言
        :return: 加密器实例
        """
        # 算法名称映射表，避免重复创建实例
        alg_map = {
            "XOR（简单快速，基础免杀）": XorEncryptor,
            "AES-256-CBC（高强度，推荐）": Aes256CbcEncryptor,
            "DES-CBC（经典算法，兼容性好）": DesCbcEncryptor,
            "RC4（流加密，高效轻便）": Rc4Encryptor,
            "ChaCha20（现代流加密，高效安全）": ChaCha20Encryptor
        }
        
        # 查找对应的加密器类
        encryptor_cls = alg_map.get(alg_full_name)
        if not encryptor_cls:
            raise ValueError(f"不支持的加密算法：{alg_full_name}")
        
        # 根据算法类型创建实例
        if encryptor_cls == XorEncryptor or encryptor_cls == Rc4Encryptor:
            return encryptor_cls(key=key)
        elif encryptor_cls == ChaCha20Encryptor:
            return encryptor_cls(key=key, nonce=nonce)
        else:
            return encryptor_cls(key=key, iv=iv)
    
    def encrypt_shellcode(self, shellcode: bytes, alg_full_name: str, key: Optional[bytes] = None, iv: Optional[bytes] = None, nonce: Optional[bytes] = None, target_lang: str = "C/C++") -> (bytes, Dict[str, Any]):
        """
        对shellcode执行加密，自动适配算法是否需要IV/nonce参数
        :param shellcode: 原始shellcode字节数据
        :param alg_full_name: 完整算法名称
        :param key: 自定义密钥（None则随机生成）
        :param iv: 自定义IV（仅AES/DES需要，None则随机生成）
        :param nonce: 自定义nonce（仅ChaCha20需要，None则随机生成）
        :param target_lang: 目标语言
        :return: 加密后的shellcode + 加密信息字典
        """
        encryptor = self.get_encryptor(alg_full_name, key, iv, nonce, target_lang)
        encrypted_shellcode, params = encryptor.encrypt(shellcode)
        return encrypted_shellcode, {
            "alg": encryptor.alg_name,
            "alg_full": alg_full_name,
            "params": params,
            "encrypted_len": len(encrypted_shellcode)
        }