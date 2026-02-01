#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件操作工具模块：仅负责文件的保存和读取，无其他业务逻辑
"""
import os

def save_file(content: str, file_path: str) -> None:
    """
    将字符串内容保存到指定文件
    :param content: 待保存的字符串内容
    :param file_path: 保存文件路径
    """
    if not isinstance(content, str):
        raise ValueError("待保存内容必须为字符串类型")
    
    # 确保目录存在
    dir_path = os.path.dirname(file_path)
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    
    # 写入文件
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

def read_file(file_path: str) -> str:
    """
    读取指定文件的内容
    :param file_path: 读取文件路径
    :return: 文件内容字符串
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"文件不存在：{file_path}")
    
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()