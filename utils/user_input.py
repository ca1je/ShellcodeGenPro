#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用户输入工具模块：仅负责交互式输入的校验和获取，无其他业务逻辑
"""

def get_user_choice(prompt: str, valid_choices: list) -> int:
    """
    获取用户有效数字选择
    :param prompt: 终端提示信息
    :param valid_choices: 有效选择列表
    :return: 用户输入的有效数字
    """
    while True:
        try:
            user_input = input(prompt).strip()
            choice = int(user_input)
            if choice in valid_choices:
                return choice
            else:
                print(f"无效选择！请从 {valid_choices} 中选择")
        except ValueError:
            print("无效输入！请输入数字类型的选项编号")

def confirm_continue(prompt: str = "是否继续？(y/n)：") -> bool:
    """
    确认用户是否继续操作
    :param prompt: 终端提示信息
    :return: 是否继续（True/False）
    """
    while True:
        choice = input(prompt).strip().lower()
        if choice in ["y", "n"]:
            return choice == "y"
        print("无效输入！请输入 y 或 n")