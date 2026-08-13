# CVE·Classifier 新版项目大纲与实施细则

## 一、项目定位

### 1. 项目名称

**CVE·Classifier**

建议论文题目：

**基于预训练语言模型的 CVE 漏洞属性自动分类研究与实现**

备选题目：

**面向 CVE 漏洞描述的多任务深度学习分类方法研究与实现**

### 2. 项目目标

以 CVE 漏洞英文描述文本为输入，利用自然语言处理和深度学习方法，自动预测漏洞对应的标准化安全属性。

项目主要研究：

1. CVE 漏洞文本的数据构建方法；
2. CVSS 属性自动预测方法；
3. 不同文本分类模型在漏洞属性预测任务中的性能差异；
4. 多任务学习在漏洞属性联合预测中的效果；
5. 类别不平衡对漏洞分类性能的影响；
6. 模型在未来新漏洞上的时间泛化能力。

---

# 二、总体技术路线

整体流程：

```text
NVD CVE API
    ↓
原始 CVE JSON 数据
    ↓
数据清洗与结构化解析
    ↓
CVSS / CWE 标签提取
    ↓
Temporal Split
    ↓
文本分类模型
    ↓
模型训练
    ↓
模型评估
    ↓
对比实验
    ↓
漏洞属性预测系统
```

原则：

> 数据构建、数据解析、数据集生成、模型训练和实验评估必须相互独立。

禁止将所有逻辑写在一个 Python 文件中。

---

# 三、数据源设计

## 3.1 数据来源

本项目采用 **CVE.org + National Vulnerability Database（NVD）双数据源架构**。

两个数据源承担不同职责：

```text
CVE.org
   │
   │ CVE 原始记录
   │ CVE ID / Description / CNA 信息
   ▼
漏洞文本事实数据
   │
   │ 通过 CVE ID 关联
   ▼
NVD
   │
   │ CVSS / CWE / CPE 等增强信息
   ▼
监督学习标签
```

### 3.1.1 CVE.org

CVE.org 作为本项目的主要漏洞事实数据源。

主要获取以下信息：

* CVE ID；
* CVE 发布时间；
* CVE 更新时间；
* CNA 信息；
* 英文漏洞描述；
* CVE Record 原始数据；
* 其他 CVE JSON 记录字段。

在模型训练过程中，优先使用 CVE.org 中的英文漏洞描述作为模型输入文本。

即：

```text
Input = CVE.org English Description
```

CVE.org 原始数据在下载后不得进行修改，完整保存在 `data/raw/cve/` 中。

---

### 3.1.2 NVD

National Vulnerability Database（NVD）作为本项目的漏洞分析和标签增强数据源。

NVD 在 CVE 信息基础上提供更加结构化的漏洞分析信息，主要包括：

* CVSS v4.0；
* CVSS v3.1；
* CVSS v3.0；
* CVSS v2；
* CVSS Base Score；
* CWE；
* CPE；
* 漏洞分析状态；
* References；
* 其他漏洞增强信息。

本项目主要利用 NVD 中的 CVSS 和 CWE 信息构造监督学习标签。

即：

```text
Label = NVD CVSS / CWE
```

NVD 数据通过 NVD CVE API 2.0 获取。

NVD 原始数据完整保存在：

```text
data/raw/nvd/
```

下载阶段不进行任何过滤和清洗。

---

## 3.2 数据关联方式

CVE.org 和 NVD 中均使用标准 CVE ID 作为漏洞唯一标识。

因此，本项目采用：

```text
cve_id
```

作为两个数据源之间的关联键。

例如：

```text
CVE.org
CVE-2025-0168
        │
        │ cve_id
        ▼
NVD
CVE-2025-0168
```

两个数据源经过解析后，通过 CVE ID 进行关联。

最终形成统一漏洞记录：

```text
cve_id
published

cve_description
nvd_description

cvss_v40_vector
cvss_v31_vector

cwe_primary
cwe_all
```

其中：

```text
cve_description
```

优先作为模型文本输入。

NVD 中的 description 保留，用于数据一致性检查和后续对比实验。

---

## 3.3 数据使用原则

第一阶段模型采用严格的输入与标签分离策略。

模型输入：

```text
CVE.org English Description
```

监督标签：

```text
NVD CVSS
```

后续 CWE 分类任务使用：

```text
NVD CWE
```

第一阶段禁止将以下字段直接作为模型输入：

```text
CVSS Vector
CVSS Base Score
Severity
CWE
SSVC
```

避免产生标签泄漏（Label Leakage）。

---

## 3.4 原始数据目录

项目目录调整为：

```text
CVE_Classifier/
├── data/
│   ├── raw/
│   │   ├── cve/
│   │   └── nvd/
│   │
│   ├── interim/
│   ├── processed/
│   └── splits/
│
├── src/
│   ├── data/
│   ├── models/
│   ├── training/
│   └── evaluation/
│
├── configs/
├── docs/
│   └── PROJECT_SPEC.md
│
├── tests/
├── outputs/
├── checkpoints/
├── notebooks/
├── requirements.txt
└── README.md
```

---

## 3.5 数据处理流程

整体数据流为：

```text
CVE.org ──→ data/raw/cve/
                    │
                    ▼
                parse_cve.py
                    │
                    ▼
              CVE interim data
                    │
                    │
                    ├───────────┐
                    │           │
                    │      merge_sources.py
                    │           │
                    ▼           ▼
NVD ─────→ data/raw/nvd/    merged data
                    │           │
                    ▼           ▼
                parse_nvd.py  processed
                                │
                                ▼
                              splits
```

逻辑上可简化为：

```text
raw
 ↓
interim
 ↓
merged
 ↓
processed
 ↓
splits
```

---

## 3.6 各目录职责

### raw

保存两个数据源的原始数据：

```text
data/raw/cve/
data/raw/nvd/
```

规则：

* 不修改；
* 不删除字段；
* 不人工修正；
* 不覆盖已有原始文件；
* 不直接用于模型训练；
* 作为整个实验的数据溯源依据。

---

### interim

保存经过程序解析后的结构化数据。

例如：

```text
cve_records.parquet
nvd_records.parquet
```

该阶段主要进行字段提取和格式标准化，不执行面向具体实验的数据筛选。

---

### processed

保存经过以下处理后的机器学习数据：

* Rejected CVE 过滤；
* 无有效英文描述样本过滤；
* CVSS 标签提取；
* 标签来源选择；
* 异常样本处理；
* CVE 与 NVD 数据关联；
* 模型所需字段生成。

---

### splits

保存最终模型训练所使用的数据：

```text
train
validation
test
future_test
```

正式实验优先采用时间切分（Temporal Split）。

---

## 3.7 数据完整性原则

整个数据处理过程必须满足：

```text
Raw Data
   ↓
可追溯
   ↓
Processed Data
   ↓
可复现
   ↓
Training Dataset
```

任何最终训练样本均应能够根据 `cve_id` 追溯至：

1. CVE.org 原始记录；
2. NVD 原始记录；
3. 标签来源；
4. 数据处理过程。

不得人工修改训练标签而不记录修改原因。

# 四、数据下载细则

## 4.1 按月下载

禁止一次下载多年数据。

采用：

```text
2024-01.json
2024-02.json
...
2025-12.json
```

的形式保存。

目录：

```text
data/raw/nvd/2024/2024-01.json
data/raw/nvd/2024/2024-02.json
...
data/raw/nvd/2025/2025-12.json
```

---

## 4.2 第一阶段下载范围

第一批：

```text
2024-01
至
2025-12
```

目的：

统计 CVSS v4.0 可用数据量。

如果数据不足，再逐步扩展：

```text
2020–2023
```

如需要长期历史实验，再扩展：

```text
2010–2019
```

---

## 4.3 下载程序职责

### download_nvd.py

负责：

- 请求 NVD API；
- 分页；
- API Key；
- 自动重试；
- 请求间隔；
- 原始 JSON 保存。

禁止：

- CVSS 解析；
- CWE 解析；
- 删除 Rejected；
- 数据清洗；
- 标签转换。

### download_range.py

负责：

- 按月份循环；
- 自动生成完整 ISO 时间；
- 调用 download_nvd；
- 已存在文件自动跳过；
- 某月失败不影响其他月份。

---

# 五、CVE 数据解析规则

## 5.1 基础字段

每条 CVE 至少提取：

```text
cve_id
source_identifier
published
last_modified
vuln_status
description
```

---

## 5.2 Description 规则

只使用：

```text
lang == "en"
```

的英文描述。

最终模型输入：

```text
description
```

第一版禁止额外加入：

```text
CWE
CVSS
severity
base_score
reference
CPE
```

避免 label leakage。

---

# 六、CVE 状态处理

原始数据保留所有状态。

解析时记录：

```text
Rejected
Analyzed
Modified
Deferred
Awaiting Analysis
Undergoing Analysis
```

等状态。

## 6.1 Rejected

规则：

```text
Rejected → 不进入训练数据
```

Rejected CVE 可以保留在 interim 数据中，但必须标记：

```text
is_trainable = false
```

---

## 6.2 推荐训练状态

第一版推荐：

```text
Analyzed
Modified
```

作为主要训练数据。

其他状态：

```text
Deferred
Awaiting Analysis
Undergoing Analysis
```

先保存，但默认不进入正式训练集。

---

# 七、CVSS 标签体系

## 7.1 主任务

第一阶段主任务：

**CVSS v4.0 Base Metrics 自动预测**

输入：

```text
CVE Description
```

输出：

```text
AV
AC
AT
PR
UI
VC
VI
VA
SC
SI
SA
```

---

# 八、CVSS v4.0 标签定义

## Attack Vector

```text
AV
```

类别：

```text
N = Network
A = Adjacent
L = Local
P = Physical
```

---

## Attack Complexity

```text
AC
```

类别：

```text
L = Low
H = High
```

---

## Attack Requirements

```text
AT
```

类别：

```text
N = None
P = Present
```

---

## Privileges Required

```text
PR
```

类别：

```text
N = None
L = Low
H = High
```

---

## User Interaction

```text
UI
```

类别：

```text
N = None
P = Passive
A = Active
```

---

## Vulnerable System Impact

```text
VC
VI
VA
```

分别表示：

```text
Confidentiality
Integrity
Availability
```

类别：

```text
H
L
N
```

---

## Subsequent System Impact

```text
SC
SI
SA
```

表示后续系统影响。

保留 CVSS v4.0 原始标准枚举。

不得自行合并类别。

---

# 九、CVSS 多来源处理规则

同一个 CVE 可能同时具有：

```text
NVD
CNA
Third-party
```

提供的 CVSS。

禁止简单使用：

```python
cvssMetricV31[0]
```

或：

```python
cvssMetricV40[0]
```

作为标签。

统一建立选择规则。

优先级：

```text
1. type == Primary 且 source == nvd@nist.gov

2. 其他 Primary

3. Secondary CNA

4. 其他 Secondary
```

同时保存：

```text
cvss_source
cvss_type
cvss_vector
```

保证实验标签可追溯。

---

# 十、CVSS 多版本数据处理

数据表同时保留：

```text
cvss_v40
cvss_v31
cvss_v30
cvss_v2
```

但不要强制把不同版本映射为相同标签。

研究实验分别进行。

推荐：

### Experiment A

```text
CVSS v3.1
```

作为大规模历史实验。

### Experiment B

```text
CVSS v4.0
```

作为新版标准实验。

---

# 十一、CWE 标签设计

CWE 作为第二阶段任务。

字段：

```text
cwe_primary
cwe_all
```

例如：

```text
cwe_primary:
CWE-89

cwe_all:
CWE-74
CWE-89
```

CWE 分类暂时不与 CVSS 分类一起训练。

完成 CVSS 实验后再增加。

---

# 十二、结构化数据 Schema

interim 数据建议：

```text
cve_id
published
last_modified
vuln_status
source_identifier

description

cvss_v40_vector
cvss_v40_source
cvss_v40_type

cvss_v31_vector
cvss_v31_source
cvss_v31_type

cvss_v30_vector
cvss_v2_vector

cwe_primary
cwe_all

is_rejected
is_trainable
```

---

# 十三、最终 CVSS v4.0 训练集 Schema

```text
cve_id
published
description

av
ac
at
pr
ui

vc
vi
va

sc
si
sa
```

原则：

一行对应一个 CVE。

---

# 十四、数据切分细则

禁止继续使用随机：

```text
6 : 2 : 2
```

作为正式实验方案。

新版采用：

**Temporal Split**

---

## 推荐第一版

### Train

```text
published < 2024-01-01
```

### Validation

```text
2024-01-01
至
2024-12-31
```

### Test

```text
2025-01-01
至
2025-12-31
```

### Future Test

```text
2026
```

Future Test 在模型开发阶段尽量不查看结果。

目的：

测试模型对未来新漏洞的泛化能力。

---

# 十五、数据泄漏控制

模型输入第一阶段只允许：

```text
description
```

禁止：

```text
CVSS vector
base score
severity
CWE
SSVC
```

因为这些字段与目标高度相关甚至直接包含答案。

后续可以设计独立实验：

```text
Description Only
```

对比：

```text
Description + CWE
```

或者：

```text
Description + Product Information
```

但必须明确标注为增强输入实验。

---

# 十六、文本预处理规则

传统模型和 Transformer 分开处理。

## 传统模型

例如：

```text
TF-IDF
TextCNN
BiLSTM
```

可以研究：

- lowercase；
- punctuation；
- stopwords；
- lemmatization。

---

## Transformer

例如：

```text
BERT
RoBERTa
DeBERTa
```

原则：

尽量保留原始文本。

不要主动删除：

```text
version number
数字
路径
符号
产品名称
权限词
攻击条件
```

例如：

```text
<= 1.3.0
/admin/
remote
authenticated
crafted request
```

这些都可能是重要漏洞语义。

---

# 十七、模型实验体系

模型实验分为四层。

## 第一层：传统机器学习 baseline

必须包含：

```text
TF-IDF + Logistic Regression
TF-IDF + Linear SVM
```

目的：

建立可靠低成本 baseline。

---

# 十八、经典深度学习 baseline

建议：

```text
TextCNN
BiLSTM
```

主要目的是和本科实验形成纵向对比。

---

# 十九、预训练语言模型

至少包含：

```text
BERT
```

推荐增加：

```text
RoBERTa
DeBERTa
```

根据硬件条件决定模型大小。

第一阶段优先：

```text
base
```

级模型。

不追求大模型规模。

---

# 二十、多任务学习模型

新版核心模型建议：

```text
            ┌── AV Head
            ├── AC Head
            ├── AT Head
            ├── PR Head
Description → Encoder
            ├── UI Head
            ├── VC Head
            ├── VI Head
            ├── VA Head
            ├── SC Head
            ├── SI Head
            └── SA Head
```

共享：

```text
Transformer Encoder
```

每个属性：

```text
独立 Linear Classification Head
```

总损失：

```text
L =
λ1 L_AV
+ λ2 L_AC
+ ...
+ λ11 L_SA
```

第一版：

```text
所有 λ = 1
```

后续再研究动态权重。

---

# 二十一、核心对比实验

至少完成以下实验。

## 实验 1

传统机器学习模型对比：

```text
LR vs SVM
```

## 实验 2

经典深度学习：

```text
TextCNN vs BiLSTM
```

## 实验 3

预训练模型：

```text
BERT vs RoBERTa vs DeBERTa
```

## 实验 4

单任务与多任务：

```text
Single-task
vs
Multi-task
```

## 实验 5

类别不平衡：

```text
CrossEntropy
vs
Weighted CrossEntropy
vs
Focal Loss
```

## 实验 6

数据切分：

```text
Random Split
vs
Temporal Split
```

Random Split 仅用于分析。

Temporal Split 作为正式结果。

---

# 二十二、评价指标

禁止只报告 Accuracy。

每个 target 至少报告：

```text
Macro Precision
Macro Recall
Macro F1
Weighted F1
Accuracy
```

主要指标：

```text
Macro-F1
```

---

# 二十三、Macro-F1 计算规则

对每个类别先计算：

```text
Precision
Recall
F1
```

再：

```text
Macro-F1 =
所有类别 F1 的平均值
```

不要使用：

```text
Macro-P 与 Macro-R 的调和平均
```

来代替 Macro-F1。

---

# 二十四、分类错误分析

每个主要实验至少输出：

```text
Confusion Matrix
Per-class Precision
Per-class Recall
Per-class F1
Support
```

重点分析：

- 少数类；
- 高频类；
- 容易混淆类别；
- 描述信息不足的 CVE；
- 标签来源冲突的 CVE。

---

# 二十五、类别不平衡处理

首先统计：

```text
label distribution
```

不得未经统计直接使用 SMOTE 等方法。

第一阶段推荐比较：

```text
普通 CrossEntropy
Weighted CrossEntropy
Focal Loss
```

主要观察：

```text
Macro-F1
Minority Recall
Minority F1
```

---

# 二十六、模型训练规范

所有实验必须固定：

```text
random_seed
```

例如：

```text
42
```

记录：

```text
model
batch_size
learning_rate
epochs
optimizer
scheduler
max_length
loss function
seed
```

模型参数统一存入：

```text
configs/
```

禁止把所有实验参数硬编码在 Python 文件中。

---

# 二十七、实验复现规范

每次实验必须保存：

```text
config
metrics
log
best checkpoint
prediction
```

目录例如：

```text
outputs/
└── bert_multitask_v1/
    ├── config.json
    ├── metrics.json
    ├── train.log
    ├── predictions.csv
    └── confusion_matrix/
```

---

# 二十八、模型选择规则

Validation：

用于：

```text
超参数选择
early stopping
checkpoint selection
```

Test：

只用于最终模型评估。

禁止根据 Test 结果反复调模型。

Future Test：

用于最终时间泛化实验。

---

# 二十九、工程实现模块

建议最终实现：

```text
src/data/
download_nvd.py
download_range.py
parse_nvd.py
build_dataset.py
split_dataset.py
```

```text
src/models/
tfidf.py
textcnn.py
bilstm.py
bert.py
multitask_transformer.py
```

```text
src/training/
train.py
losses.py
trainer.py
```

```text
src/evaluation/
metrics.py
evaluate.py
error_analysis.py
```

---

# 三十、最终预测系统

完成模型实验后增加：

```text
predict.py
```

输入：

```text
CVE description
```

输出例如：

```text
Attack Vector: Network
confidence: 0.95

Attack Complexity: Low
confidence: 0.91

Privileges Required: Low
confidence: 0.88
```

后续可增加：

```text
FastAPI
```

形成简单 REST API。

---

# 三十一、论文结构建议

## 第 1 章 绪论

### 1.1 研究背景与意义

### 1.2 国内外研究现状

### 1.3 当前方法存在的问题

重点：

- 漏洞数量增长；
- 人工分析成本；
- 标签体系标准化；
- 长尾类别；
- 时间泛化问题。

### 1.4 研究内容

### 1.5 主要贡献

### 1.6 论文结构

---

# 三十二、第 2 章 相关理论与技术

## 2.1 CVE 与 NVD

## 2.2 CVSS

### 2.2.1 CVSS v3.1

### 2.2.2 CVSS v4.0

## 2.3 CWE

## 2.4 文本分类

## 2.5 Transformer

## 2.6 预训练语言模型

## 2.7 多任务学习

## 2.8 类别不平衡问题

---

# 三十三、第 3 章 数据集构建与分析

## 3.1 数据来源

## 3.2 NVD 数据采集

## 3.3 数据解析

## 3.4 CVSS 标签提取

## 3.5 标签来源选择

## 3.6 异常 CVE 处理

## 3.7 数据清洗

## 3.8 时间划分方法

## 3.9 标签分布分析

## 3.10 本章小结

---

# 三十四、第 4 章 漏洞属性分类模型设计

## 4.1 总体方案

## 4.2 传统机器学习模型

## 4.3 TextCNN

## 4.4 BiLSTM

## 4.5 BERT

## 4.6 DeBERTa

## 4.7 多任务 Transformer

## 4.8 类别不平衡损失函数

## 4.9 模型训练方法

## 4.10 本章小结

---

# 三十五、第 5 章 实验与结果分析

## 5.1 实验环境

## 5.2 数据集统计

## 5.3 实验设置

## 5.4 评价指标

## 5.5 Baseline 实验

## 5.6 Transformer 模型对比

## 5.7 单任务与多任务对比

## 5.8 类别不平衡实验

## 5.9 时间泛化实验

## 5.10 消融实验

## 5.11 错误分析

## 5.12 本章小结

---

# 三十六、第 6 章 漏洞分类系统实现

## 6.1 系统总体设计

## 6.2 数据模块

## 6.3 模型模块

## 6.4 推理模块

## 6.5 API

## 6.6 使用示例

---

# 三十七、第 7 章 总结与展望

## 7.1 研究总结

## 7.2 主要成果

## 7.3 局限性

包括：

```text
CVSS 标签具有人工主观差异
不同 CNA 评分不完全一致
类别分布不平衡
新 CVSS v4.0 样本规模有限
```

## 7.4 后续研究

包括：

```text
CWE 多标签分类
领域预训练模型
知识蒸馏
大语言模型
漏洞知识图谱
跨数据库数据融合
```

---

# 三十八、开发阶段安排

## Phase 1 · 数据下载

完成：

```text
download_nvd.py
download_range.py
```

下载：

```text
2024–2025
```

---

## Phase 2 · 数据解析

完成：

```text
parse_nvd.py
```

统计：

```text
CVSS v4.0 数量
CVSS v3.1 数量
CWE 数量
Rejected 数量
```

---

## Phase 3 · 数据集生成

完成：

```text
build_dataset.py
split_dataset.py
```

生成：

```text
train
validation
test
```

---

## Phase 4 · Baseline

先做：

```text
TF-IDF + Logistic Regression
TF-IDF + SVM
```

---

## Phase 5 · Transformer

完成：

```text
BERT
```

再增加：

```text
DeBERTa
```

---

## Phase 6 · Multi-task

完成：

```text
Shared Encoder
+
Multiple Classification Heads
```

---

## Phase 7 · 实验

完成：

```text
模型对比
Loss 对比
Temporal Split
Error Analysis
```

---

## Phase 8 · 系统

完成：

```text
predict.py
FastAPI
README
```

---

# 三十九、当前阶段的严格执行顺序

目前只进行：

```text
1. 完成批量下载代码

2. 下载 2024–2025 NVD 原始数据

3. 检查数据完整性

4. 开发 parse_nvd.py

5. 统计 CVSS 数据覆盖率
```

在第 5 步完成之前：

**不开始训练 BERT。**

原因：

必须先确认真实数据规模和标签分布，再确定最终实验设计。

---

# 四十、项目最重要的五条规则

1. **Raw 数据永远不修改。**

2. **模型输入和目标标签严格分离，防止数据泄漏。**

3. **同一个 CVE 多个 CVSS 来源必须按照统一规则选择。**

4. **正式实验采用 Temporal Split，而不是只采用随机切分。**

5. **所有实验必须可复现，包括数据、参数、模型和评价指标。**