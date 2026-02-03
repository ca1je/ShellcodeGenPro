# ShellcodeGenPro

ShellcodeGenPro 是一个功能强大的 Shellcode 加密和Loader生成工具，支持从 bin 文件加载 shellcode、多种加密算法、多种输出格式和多语言加载器生成。

## 功能特性

### 🚀 核心功能
- **Bin 文件转换**：从 bin 文件加载并转换为原始 shellcode
- **多重加密**：支持多种加密算法，可进行多次加密
- **灵活格式化**：支持多种输出格式和编程语言
- **加载器生成**：生成多种语言的原始加载器和解密加载器

### 🔒 支持的加密算法
- AES-256-CBC
- DES-CBC
- XOR
- RC4
- ChaCha20

### 📝 支持的输出格式
- 十六进制格式
- 字节数组格式

### 💻 支持的编程语言
- C
- Python

> 注：Go、Ruby、C#、Java 等语言的支持正在测试中

### 🔧 其他特性
- 支持字符串和十六进制两种密钥输入方式
- 自动适配密钥长度
- 详细的加密信息记录
- 友好的命令行交互界面

## 安装

### 环境要求
- Python 3.7+
- pip

### 安装依赖

```bash
pip install -r requirements.txt
```

## 使用教程

### 基本使用流程

1. **加载 Bin 文件**：输入 bin 文件路径，转换为原始 shellcode
2. **选择加密**：可选择是否对 shellcode 进行加密，支持多次加密
3. **格式化输出**：选择输出格式和目标编程语言
4. **生成加载器**：选择生成原始加载器或解密加载器

## 项目结构

```
ShellcodeGenPro/
├── core/
│   ├── bin/            # Bin 文件处理模块
│   ├── encrypt/        # 加密模块
│   ├── format/         # 格式化模块
│   ├── loader/         # 加载器生成模块
│   └── __init__.py
├── utils/
│   ├── file_operate.py # 文件操作工具
│   ├── user_input.py   # 用户输入工具
│   └── __init__.py
├── main.py             # 主入口
├── requirements.txt    # 依赖文件
└── Readme.md           # 说明文档
```

## 核心模块说明

### 1. Bin 处理模块
- 负责从 bin 文件加载并转换为原始 shellcode

### 2. 加密模块
- 实现多种加密算法
- 支持字符串和十六进制密钥输入
- 记录加密历史

### 3. 格式化模块
- 将 shellcode 转换为不同格式
- 支持多种编程语言

### 4. 加载器生成模块
- 生成原始加载器
- 生成解密加载器（适配加密历史）

## 扩展方法

### 扩展加密算法

要添加新的加密算法，请按照以下步骤操作：

1. **创建加密器类**：在 `core/encrypt/` 目录下创建一个新的加密器文件（如 `new_encrypt.py`），继承自 `BaseEncryptor` 基类
2. **实现必要方法**：
   - `alg_name` 属性：返回算法名称
   - `alg_full_name` 属性：返回算法完整名称
   - `__init__` 方法：初始化加密器，处理密钥等参数
   - `encrypt` 方法：实现加密逻辑
3. **注册加密器**：在 `core/encrypt/encrypt_manager.py` 文件中：
   - 导入新的加密器类
   - 在 `_encryptors` 列表中添加新的加密器实例
   - 在 `alg_map` 字典中添加算法名称映射
4. **更新加载器**：确保新的加密算法在解密加载器中也能正确处理

### 扩展编程语言

要添加新的编程语言支持，请按照以下步骤操作：

1. **创建加载器类**：
   - 在 `core/loader/raw_loader/` 目录下创建原始加载器文件（如 `new_raw_loader.py`）
   - 在 `core/loader/decrypt_loader/` 目录下创建解密加载器文件（如 `new_decrypt_loader.py`）
   - 两个文件都需要继承自 `BaseLoader` 基类并实现必要方法
2. **实现必要方法**：
   - `lang_name` 属性：返回语言名称
   - `generate_raw` 方法：生成原始加载器代码
   - `generate_decrypt` 方法：生成解密加载器代码
3. **注册加载器**：
   - 在 `core/loader/raw_loader/raw_loader_factory.py` 文件的 `_loader_map` 中添加新的原始加载器
   - 在 `core/loader/decrypt_loader/decrypt_loader_factory.py` 文件的 `_loader_map` 中添加新的解密加载器
4. **更新语言列表**：在 `core/loader/__init__.py` 文件的 `LOADER_LANGS` 列表中添加新的语言名称

## 注意事项

1. **密钥安全**：加密时生成的密钥信息请妥善保存，解密加载器需要使用(项目运行时会自动临时保存，并自动加载到加载器中)
2. **文件路径**：输入 bin 文件路径时，请确保路径正确
3. **依赖安装**：使用前请确保已安装所有依赖
4. **加载器使用**：生成加载器后，需要将格式化后的 shellcode 填入加载器的占位符中

## 版本历史

### v2.4.6.3
- 完善go语言加载器生成
- 优化了交互体验

### v2.4.3
- 修复C语言和Python记载器生成问题

### v2.4.2
- 修复了加密模块的密钥处理问题
- 增强了命令行交互体验
- 优化了错误处理
- 优化了加密算法实现

### v2.4.1
- 修复了格式化输出的问题
- 改进了加载器生成逻辑

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目！

## 许可证

本项目采用 MIT 许可证。

## 免责声明

本工具仅用于学习和研究目的，请勿用于任何非法活动。使用本工具产生的任何后果，由使用者自行承担。

---

**ShellcodeGenPro** - 让 Shellcode 生成和加密变得简单高效！
