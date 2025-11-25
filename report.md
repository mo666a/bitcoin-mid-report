# 比特币区块链系统项目重点报告

## 一、项目概述

项目用 Python 做了一个非常简化版本的“比特币区块链系统”。整个程序只靠 Python 的标准库加上 cryptography 库，同时用 Tkinter 做一个简单的图形界面，保证所有操作都能在界面里完成。

目前系统能实现这些功能：

生成钱包和密钥（椭圆曲线密钥对）
创建交易、对交易进行数字签名和验证
构建区块并进行简单的工作量证明挖矿
查看区块链、查看待确认交易、查询任意地址余额
图形界面上能操作所有功能，包括生成钱包、创建交易、挖矿、查看链等等


---

## 二、背景知识

### 1. 椭圆曲线与 ECDSA

在比特币体系里，交易签名用的是 ECDSA（椭圆曲线数字签名算法），比特币使用的曲线叫 secp256k1。生成密钥的代码：

```python
private_key = ec.generate_private_key(ec.SECP256K1())
```

生成出来的私钥可以用来给交易签名，公钥用来验证签名。

椭圆曲线的好处有两点：

-- 安全性比较高，但密钥长度不需要特别长  
-- 性能不错，适合实际应用  

---

### 2. 地址生成机制

比特币的地址是对公钥做一系列哈希之后的结果。  
项目为简单，只用了 SHA-256，然后取前 20 字节作为地址。

流程：

(1). 把公钥序列化成 X9.62 Uncompressed 格式  
(2). 对它做一次 SHA-256  
(3). 取哈希前 20 字节当作地址（就是 40 个十六进制字符）  

示例代码如下：

```python
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
sha = hashlib.sha256(public_bytes).hexdigest()
address = sha[:40]
```


---

## 三、工作量证明（PoW）

挖矿的过程就是不停地改 nonce，然后算区块的哈希，只要哈希值前面有足够多的“0”，就算挖成功。

代码：

```python
while not computed_hash.startswith('0' * self.difficulty):
    block.nonce += 1
    computed_hash = block.compute_hash()
```

难度越高，需要尝试的次数越多，挖矿就越慢。  

---

## 四、系统设计结构

整个系统围绕类：

-- Transaction：交易类  
-- Block：区块类  
-- Blockchain：链的管理类  
-- BlockchainGUI：图形界面  

每个模块的职责都比较单一，整体结构不算复杂。

---

## 五、密钥与地址生成模块

生成密钥：

```python
private_key, public_key = generate_keys()
```

根据公钥生成地址：

```python
address = address_from_public(public_key)
```

公钥验证、私钥签名基于 cryptography 库。

---

## 六、交易模块

一笔交易包含：

发送方地址
接收方地址
金额
 时间
 公钥
 签名

签名过程：

```python
tx.sign_transaction(private_key)
```


---

## 七、挖矿模块

挖矿的大致流程：

1. 创建矿工奖励交易（sender 写成 “MINING”）  
2. 把奖励交易和所有待确认交易一起放进一个新区块  
3. 对这个区块执行 PoW  
4. 找到满足条件的哈希之后，把区块加到链上  


---

## 八、图形界面模块

图形界面用 Tkinter 写的，功能大概包括：

-- 生成钱包  
-- 创建交易  
-- 挖矿  
-- 浏览整个区块链  
-- 输入地址查询余额  


---

## 九、当前进展总结

目前整个项目已经完成了核心部分：

-- 区块、交易、区块链等基本结构都能正常工作  
-- ECDSA 的签名和验证流程已经能跑通  
-- 挖矿和工作量证明能够正常执行  
-- 图形界面的所有模块都能正常使用  


