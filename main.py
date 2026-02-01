#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShellcodeGenPro 入口（仅流程调度，模块化调用核心功能）
"""
import os
import sys

# 修复Python路径，确保模块化导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入通用工具（模块化）
from utils.user_input import get_user_choice, confirm_continue
from utils.file_operate import save_file

# 导入核心业务模块（模块化，导入路径全部正确）
from core.bin.bin_handler import BinFileHandler
from core.encrypt.encrypt_manager import EncryptManager, EncryptionHistory
from core.format.format_manager import FormatManager
from core.format import OUTPUT_FORMATS, LANG_TYPES
from core.loader.raw_loader import RawLoaderFactory
from core.loader.decrypt_loader import DecryptLoaderFactory
from core.loader import LOADER_LANGS

def main():
    print("="*50)
    print("        ShellcodeGenPro 2.4.5")
    print("="*50)

    # ---------------------- 步骤1：bin→raw shellcode（调用bin模块） ----------------------
    print("\n【步骤1：读取bin文件，生成原始shellcode】")
    bin_path = input("请输入bin文件路径（如：payload.bin）：").strip()
    bin_handler = BinFileHandler()

    try:
        shellcode = bin_handler.load_bin_to_shellcode(bin_path)
        print(f"✅ 成功读取bin文件，shellcode长度：{len(shellcode)} 字节")
    except Exception as e:
        print(f"❌ 读取bin文件失败：{e}")
        return

    # ---------------------- 步骤2：多次多类型加密（调用encrypt模块，支持字符串/十六进制密钥） ----------------------
    print("\n【步骤2：shellcode加密（支持多次、多种算法，支持字符串/十六进制密钥）】")
    encrypt_manager = EncryptManager()
    encryption_history = EncryptionHistory()

    while True:
        if not confirm_continue("是否需要对shellcode进行加密？(y/n)："):
            break

        # 选择加密算法
        print("\n支持的加密算法：")
        for idx, alg_name in enumerate(encrypt_manager.supported_algorithms, 1):
            print(f"  {idx}. {alg_name}")
        alg_choice = get_user_choice("请选择加密算法编号：", list(range(1, len(encrypt_manager.supported_algorithms)+1)))
        alg_name = encrypt_manager.supported_algorithms[alg_choice-1]

        # ---------------------- 核心修改：支持字符串/十六进制双格式密钥输入 ----------------------
        custom_key = None
        custom_iv = None
        custom_nonce = None
        print(f"\n当前选择加密算法：{alg_name}")
        use_custom_key = confirm_continue("是否使用自定义密钥？（y/n，n则自动生成随机密钥）：")

        if use_custom_key:
            try:
                custom_nonce = None
                if "XOR" in alg_name or "RC4" in alg_name:
                    # XOR/RC4 算法：无IV/nonce，仅密钥（支持字符串/十六进制，长度不限）
                    key_type = get_user_choice("请选择密钥输入类型：\n  1. 字符串（直观，如：mysecret123）\n  2. 十六进制（高精度，如：a1b2c3d4）", [1, 2])
                    if key_type == 1:
                        key_str = input(f"请输入自定义{alg_name}密钥（字符串格式）：").strip()
                        if not key_str:
                            raise ValueError("字符串密钥不能为空")
                        custom_key = key_str.encode('utf-8')  # 字符串转字节（UTF-8编码）
                        print(f"✅ 自定义{alg_name}字符串密钥加载成功")
                        print(f"   密钥原文：{key_str}")
                        print(f"   密钥字节长度：{len(custom_key)} 字节")
                        print(f"   密钥十六进制：{custom_key.hex()}")
                    else:
                        key_hex = input(f"请输入自定义{alg_name}密钥（十六进制格式）：").strip()
                        if not key_hex:
                            raise ValueError("十六进制密钥不能为空")
                        custom_key = bytes.fromhex(key_hex)
                        print(f"✅ 自定义{alg_name}十六进制密钥加载成功")
                        print(f"   密钥字节长度：{len(custom_key)} 字节")
                        print(f"   密钥十六进制：{custom_key.hex()}")
                elif "AES-256-CBC" in alg_name:
                    # AES-256-CBC：密钥32字节，IV 16字节（支持字符串/十六进制，自动适配长度）
                    print("\n--- 密钥配置（AES-256-CBC 要求32字节）---")
                    key_type = get_user_choice("请选择密钥输入类型：\n  1. 字符串（自动补全/截断为32字节）\n  2. 十六进制（必须32字节，64个十六进制字符）", [1, 2])
                    if key_type == 1:
                        key_str = input("请输入AES-256-CBC密钥（字符串格式）：").strip()
                        if not key_str:
                            raise ValueError("字符串密钥不能为空")
                        # 字符串转字节，自动补全（空格）或截断为32字节，保证算法要求
                        custom_key = key_str.encode('utf-8').ljust(32, b' ')[0:32]
                        print(f"✅ 自定义AES-256-CBC字符串密钥加载成功（自动适配32字节）")
                        print(f"   密钥原文：{key_str}")
                        print(f"   适配后密钥十六进制：{custom_key.hex()}")
                    else:
                        key_hex = input("请输入AES-256-CBC密钥（十六进制格式，64个字符）：").strip()
                        custom_key = bytes.fromhex(key_hex)
                        if len(custom_key) != 32:
                            raise ValueError(f"AES-256-CBC 密钥必须为32字节，当前输入为 {len(custom_key)} 字节")
                        print(f"✅ 自定义AES-256-CBC十六进制密钥加载成功")

                    print("\n--- IV配置（AES-256-CBC 要求16字节）---")
                    iv_type = get_user_choice("请选择IV输入类型：\n  1. 字符串（自动补全/截断为16字节）\n  2. 十六进制（必须16字节，32个十六进制字符）", [1, 2])
                    if iv_type == 1:
                        iv_str = input("请输入AES-256-CBC IV（字符串格式）：").strip()
                        if not iv_str:
                            raise ValueError("字符串IV不能为空")
                        # 字符串转字节，自动补全（空格）或截断为16字节，保证算法要求
                        custom_iv = iv_str.encode('utf-8').ljust(16, b' ')[0:16]
                        print(f"✅ 自定义AES-256-CBC字符串IV加载成功（自动适配16字节）")
                        print(f"   IV原文：{iv_str}")
                        print(f"   适配后IV十六进制：{custom_iv.hex()}")
                    else:
                        iv_hex = input("请输入AES-256-CBC IV（十六进制格式，32个字符）：").strip()
                        custom_iv = bytes.fromhex(iv_hex)
                        if len(custom_iv) != 16:
                            raise ValueError(f"AES-256-CBC IV 必须为16字节，当前输入为 {len(custom_iv)} 字节")
                        print(f"✅ 自定义AES-256-CBC十六进制IV加载成功")
                elif "DES-CBC" in alg_name:
                    # DES-CBC：密钥8字节，IV 8字节（支持字符串/十六进制，自动适配长度）
                    print("\n--- 密钥配置（DES-CBC 要求8字节）---")
                    key_type = get_user_choice("请选择密钥输入类型：\n  1. 字符串（自动补全/截断为8字节）\n  2. 十六进制（必须8字节，16个十六进制字符）", [1, 2])
                    if key_type == 1:
                        key_str = input("请输入DES-CBC密钥（字符串格式）：").strip()
                        if not key_str:
                            raise ValueError("字符串密钥不能为空")
                        # 字符串转字节，自动补全（空格）或截断为8字节，保证算法要求
                        custom_key = key_str.encode('utf-8').ljust(8, b' ')[0:8]
                        print(f"✅ 自定义DES-CBC字符串密钥加载成功（自动适配8字节）")
                        print(f"   密钥原文：{key_str}")
                        print(f"   适配后密钥十六进制：{custom_key.hex()}")
                    else:
                        key_hex = input("请输入DES-CBC密钥（十六进制格式，16个字符）：").strip()
                        custom_key = bytes.fromhex(key_hex)
                        if len(custom_key) != 8:
                            raise ValueError(f"DES-CBC 密钥必须为8字节，当前输入为 {len(custom_key)} 字节")
                        print(f"✅ 自定义DES-CBC十六进制密钥加载成功")

                    print("\n--- IV配置（DES-CBC 要求8字节）---")
                    iv_type = get_user_choice("请选择IV输入类型：\n  1. 字符串（自动补全/截断为8字节）\n  2. 十六进制（必须8字节，16个十六进制字符）", [1, 2])
                    if iv_type == 1:
                        iv_str = input("请输入DES-CBC IV（字符串格式）：").strip()
                        if not iv_str:
                            raise ValueError("字符串IV不能为空")
                        # 字符串转字节，自动补全（空格）或截断为8字节，保证算法要求
                        custom_iv = iv_str.encode('utf-8').ljust(8, b' ')[0:8]
                        print(f"✅ 自定义DES-CBC字符串IV加载成功（自动适配8字节）")
                        print(f"   IV原文：{iv_str}")
                        print(f"   适配后IV十六进制：{custom_iv.hex()}")
                    else:
                        iv_hex = input("请输入DES-CBC IV（十六进制格式，16个字符）：").strip()
                        custom_iv = bytes.fromhex(iv_hex)
                        if len(custom_iv) != 8:
                            raise ValueError(f"DES-CBC IV 必须为8字节，当前输入为 {len(custom_iv)} 字节")
                        print(f"✅ 自定义DES-CBC十六进制IV加载成功")
                elif "ChaCha20" in alg_name:
                    # ChaCha20：密钥32字节，nonce 16字节（支持字符串/十六进制，自动适配长度）
                    print("\n--- 密钥配置（ChaCha20 要求32字节）---")
                    key_type = get_user_choice("请选择密钥输入类型：\n  1. 字符串（自动补全/截断为32字节）\n  2. 十六进制（必须32字节，64个十六进制字符）", [1, 2])
                    if key_type == 1:
                        key_str = input("请输入ChaCha20密钥（字符串格式）：").strip()
                        if not key_str:
                            raise ValueError("字符串密钥不能为空")
                        # 字符串转字节，自动补全（空格）或截断为32字节，保证算法要求
                        custom_key = key_str.encode('utf-8').ljust(32, b' ')[0:32]
                        print(f"✅ 自定义ChaCha20字符串密钥加载成功（自动适配32字节）")
                        print(f"   密钥原文：{key_str}")
                        print(f"   适配后密钥十六进制：{custom_key.hex()}")
                    else:
                        key_hex = input("请输入ChaCha20密钥（十六进制格式，64个字符）：").strip()
                        custom_key = bytes.fromhex(key_hex)
                        if len(custom_key) != 32:
                            raise ValueError(f"ChaCha20 密钥必须为32字节，当前输入为 {len(custom_key)} 字节")
                        print(f"✅ 自定义ChaCha20十六进制密钥加载成功")

                    print("\n--- Nonce配置（ChaCha20 要求16字节）---")
                    nonce_type = get_user_choice("请选择Nonce输入类型：\n  1. 字符串（自动补全/截断为16字节）\n  2. 十六进制（必须16字节，32个十六进制字符）", [1, 2])
                    if nonce_type == 1:
                        nonce_str = input("请输入ChaCha20 Nonce（字符串格式）：").strip()
                        if not nonce_str:
                            raise ValueError("字符串Nonce不能为空")
                        # 字符串转字节，自动补全（空格）或截断为16字节，保证算法要求
                        custom_nonce = nonce_str.encode('utf-8').ljust(16, b' ')[0:16]
                        print(f"✅ 自定义ChaCha20字符串Nonce加载成功（自动适配16字节）")
                        print(f"   Nonce原文：{nonce_str}")
                        print(f"   适配后Nonce十六进制：{custom_nonce.hex()}")
                    else:
                        nonce_hex = input("请输入ChaCha20 Nonce（十六进制格式，32个字符）：").strip()
                        custom_nonce = bytes.fromhex(nonce_hex)
                        if len(custom_nonce) != 16:
                            raise ValueError(f"ChaCha20 Nonce 必须为16字节，当前输入为 {len(custom_nonce)} 字节")
                        print(f"✅ 自定义ChaCha20十六进制Nonce加载成功")
            except ValueError as e:
                print(f"❌ 自定义密钥/IV输入无效：{e}")
                print("⚠️  放弃本次加密，返回重新选择")
                continue
            except Exception as e:
                print(f"❌ 自定义密钥/IV解析失败：{e}")
                print("⚠️  放弃本次加密，返回重新选择")
                continue

        # ---------------------- 加密执行：传递自定义密钥/IV/nonce ----------------------
        try:
            # 记录加密前信息
            print(f"\n📋 开始加密...")
            print(f"   当前轮次：{len(encryption_history.get_full_history()) + 1}")
            print(f"   加密算法：{alg_name}")
            print(f"   加密前shellcode长度：{len(shellcode)} 字节")

            # 根据算法类型传递对应参数
            if "ChaCha20" in alg_name:
                shellcode, encrypt_info = encrypt_manager.encrypt_shellcode(
                    shellcode=shellcode,
                    alg_full_name=alg_name,
                    key=custom_key,
                    nonce=custom_nonce
                )
            else:
                shellcode, encrypt_info = encrypt_manager.encrypt_shellcode(
                    shellcode=shellcode,
                    alg_full_name=alg_name,
                    key=custom_key,
                    iv=custom_iv
                )
            encryption_history.add_encrypt_info(encrypt_info)
            print(f"\n✅ 加密成功！当前shellcode长度：{len(shellcode)} 字节")

            # 打印密钥信息（方便用户记录，解密加载器需要）
            print(f"🔑 加密密钥信息（请妥善保存）：")
            if "key_hex" in encrypt_info["params"]:
                print(f"   密钥（十六进制）：{encrypt_info['params']['key_hex']}")
            if "iv_hex" in encrypt_info["params"]:
                print(f"   IV（十六进制）：{encrypt_info['params']['iv_hex']}")
            if "nonce_hex" in encrypt_info["params"]:
                print(f"   Nonce（十六进制）：{encrypt_info['params']['nonce_hex']}")

            # 打印当前加密历史顺序
            current_history = encryption_history.get_full_history()
            print(f"\n📊 当前加密顺序：")
            for i, info in enumerate(current_history, 1):
                print(f"   第{i}轮：{info['alg']}")
            print(f"   总计：{len(current_history)}轮加密")
        except Exception as e:
            print(f"❌ 加密失败：{e}")
            continue

        if not confirm_continue("是否需要继续进行其他加密？(y/n)："):
            break

    # ---------------------- 步骤3：灵活格式化输出（无修改） ----------------------
    print("\n【步骤3：shellcode格式化输出与保存】")
    format_manager = FormatManager()

    if confirm_continue("是否需要对shellcode进行格式化处理？(y/n)："):
        # 选择输出格式
        print("\n支持的输出格式：")
        for idx, fmt_name in enumerate(OUTPUT_FORMATS.keys(), 1):
            print(f"  {idx}. {fmt_name}")
        fmt_choice = get_user_choice("请选择输出格式编号：", list(range(1, len(OUTPUT_FORMATS)+1)))
        fmt_name = list(OUTPUT_FORMATS.keys())[fmt_choice-1]

        # 选择目标语言
        print("\n支持的目标编程语言：")
        for idx, lang_name in enumerate(LANG_TYPES.keys(), 1):
            print(f"  {idx}. {lang_name}")
        lang_choice = get_user_choice("请选择编程语言编号：", list(range(1, len(LANG_TYPES)+1)))
        lang_name = list(LANG_TYPES.keys())[lang_choice-1]

        # 选择是否分组
        is_grouped = confirm_continue("是否需要分组输出（便于阅读）？(y/n)：")
        group_size = 16 if is_grouped else None

        # 执行格式化
        try:
            formatted_content = format_manager.format(
                shellcode=shellcode,
                output_format=fmt_name,
                lang_type=lang_name,
                group_size=group_size
            )
            print("\n✅ 格式化成功！结果如下：")
            print("-"*30)
            print(formatted_content)
            print("-"*30)
        except Exception as e:
            print(f"❌ 格式化失败：{e}")
            return

        # 保存格式化结果
        if confirm_continue("是否需要将格式化结果保存到文件？(y/n)："):
            default_filename = f"formatted_shellcode_{lang_name.lower()}.txt"
            filename = input(f"请输入保存文件名（默认：{default_filename}）：").strip() or default_filename
            try:
                save_file(formatted_content, filename)
                print(f"✅ 保存成功！文件路径：{os.path.abspath(filename)}")
            except Exception as e:
                print(f"❌ 保存失败：{e}")

    # ---------------------- 步骤4：双模式加载器生成（无修改） ----------------------
    print("\n【步骤4：shellcode加载器生成（双模式）】")
    if confirm_continue("是否需要生成shellcode加载器？(y/n)："):
        # 选择加载器模式
        print("\n加载器生成模式：")
        print("  1. 手动生成：原始加载器（无解密）")
        print("  2. 自动生成：解密加载器（适配加密历史）")
        loader_mode = get_user_choice("请选择加载器模式编号：", [1, 2])

        # 选择加载器语言
        print("\n支持的加载器编程语言：")
        for idx, lang in enumerate(LOADER_LANGS, 1):
            print(f"  {idx}. {lang}")
        lang_choice = get_user_choice("请选择加载器编程语言编号：", list(range(1, len(LOADER_LANGS)+1)))
        loader_lang = LOADER_LANGS[lang_choice-1]

        # 生成加载器
        try:
            if loader_mode == 1:
                # 模式1：原始加载器
                loader_factory = RawLoaderFactory()
                loader_content = loader_factory.create_loader(loader_lang, len(shellcode))
                default_filename = f"raw_loader_{loader_lang.lower()}.txt"
            else:
                # 模式2：解密加载器
                if encryption_history.is_empty():
                    print("⚠️  无加密历史，自动生成原始加载器！")
                    loader_factory = RawLoaderFactory()
                    loader_content = loader_factory.create_loader(loader_lang, len(shellcode))
                    default_filename = f"raw_loader_{loader_lang.lower()}.txt"
                else:
                    loader_factory = DecryptLoaderFactory()
                    loader_content = loader_factory.create_loader(loader_lang, len(shellcode), encryption_history)
                    default_filename = f"decrypt_loader_{loader_lang.lower()}.txt"

            # 保存加载器
            filename = input(f"请输入加载器保存文件名（默认：{default_filename}）：").strip() or default_filename
            save_file(loader_content, filename)
            print(f"✅ 加载器生成并保存成功！文件路径：{os.path.abspath(filename)}")
            print(f"📌 提示：请将格式化后的shellcode填入加载器的占位符中运行")
        except Exception as e:
            print(f"❌ 加载器生成失败：{e}")

    print("\n🎉 所有操作完成！")

if __name__ == "__main__":
    main()