比特币区块链系统项目中期报告
一、项目概述

本项目实现了一个简化的比特币区块链系统。程序使用 Python 语言并依赖标准库和 cryptography 库，可在桌面环境通过 Tkinter 提供图形界面。该系统提供以下核心功能：

钱包与密钥生成：用户可以生成椭圆曲线密钥对及对应钱包地址

交易签名与验证：交易签名与验证

区块构建与挖矿：通过简化工作量证明（Proof-of-Work）机制挖矿，新区块包含奖励交易和待确认交易

链校验与查询：用户可查看区块链、待确认交易及查询任意地址余额

图形化操作：提供图形界面包含钱包、交易、挖矿、链浏览和余额查询等页面

二、背景知识
1. 椭圆曲线与 ECDSA

比特币使用的数字签名算法是 ECDSA（椭圆曲线数字签名算法），使用的曲线是 secp256k1。该曲线由 SEC 组织定义，具有高效运算速度和安全性。

系统通过 generate_keys() 实现：

private_key = ec.generate_private_key(ec.SECP256K1())


生成私钥和公钥。

2. 地址生成

地址不是公钥本身，而是公钥经过哈希处理得到：

先序列化公钥（X9.62 Uncompressed 格式）

对字节串执行 SHA-256

取前 20 个字节作为地址（40 位十六进制字符）

代码中：

sha = hashlib.sha256(public_bytes).hexdigest()
address = sha[:40]


（简化版本，不包含 Base58Check）

三、工作量证明机制（PoW）

PoW 通过不断递增 nonce 直到得到满足“前 difficulty 位为 0”的哈希值：

while not computed_hash.startswith('0' * self.difficulty):
    block.nonce += 1
    computed_hash = block.compute_hash()


难度越大，挖矿越慢。

四、系统设计

系统包含核心类：

Transaction —— 交易对象

Block —— 区块对象

Blockchain —— 链管理器

BlockchainGUI —— Tkinter 图形界面

五、密钥与地址生成模块
1. 生成密钥
private_key, public_key = generate_keys()

2. 生成地址
address = address_from_public(public_key)

六、交易模块

交易包括字段：

发送方地址

接收方地址

金额

时间戳

公钥（验证用）

签名

通过：

tx.sign_transaction(private_key)


实现 ECDSA 签名。

七、挖矿模块

挖矿步骤：

创建奖励交易（sender="MINING"）

将待确认交易与奖励交易放入新区块

进行 PoW

添加区块到链中

八、图形界面模块

界面包含：

钱包生成页

交易创建页

挖矿页

链浏览页

余额查询页

所有操作均可在界面中完成。

九、当前进度总结

截至中期：
核心数据结构已全部实现

签名与验证流程工作正常

PoW、挖矿流程已实现



