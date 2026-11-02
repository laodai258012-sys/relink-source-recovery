# Relink 源码恢复记录

本仓库保存从 `Relink枪皮助手1026-1(修复).exe` 恢复的宏文本、分析工具、索引和验证结果。
**不是原作者的完整 C++ 工程，也不保证反编译结果可以重新编译。**

## 阅读入口

- `recovered_source/`：完整宏，包含 2,281 个动作、808 处脚本、585 处条件以及界面定义。
- `recovered_source/macro.readable.json`：解密后可读的完整宏。
- `recovered_source/action_scripts/`：1,012 个去重后的脚本/条件文件。
- `recovered_helper/`：重建的小型 x86 助手源码及说明。
- 根目录 Python 文件和 `ghidra_scripts/`：本次分析、提取和验证工具。
- `native_recovered/`：函数索引、失败清单和验证记录；完整伪代码在 Release 附件中。
- `RECOVERY_REPORT.md`：完整恢复包的说明，其中的目录路径以恢复包为准。
- `upstream_provenance.md`：公开上游参考来源与适用范围。

## 全部恢复结果

在本仓库的 [Releases](https://github.com/laodai258012-sys/relink-source-recovery/releases) 下载 `source_recovery_bundle.zip`。
压缩包包含全部 **119,275 个 C 风格伪代码文件**、反汇编、分析用 PE、22 项资源、宏源码、工具和上游参考归档。
源码总量较大，因此完整原生分析结果作为 Release 附件保存，不重复放入 Git 历史。
包内 `native_recovered/all_native_pseudocode.zip` 分为主程序、叶函数候选和资源编辑器三个目录。
仍有 50 个范围未成功生成伪代码，详见失败清单；它们的机器码仍保留在分析资料中。

附件大小：254,142,360 字节。SHA-256 见 `SHA256SUMS.txt`。

## 复现与限制

工具使用 Python；依赖版本见 `requirements-recovery.txt`，原生反编译使用 Ghidra 11.0.3 / JDK 17。
根目录结构与原分析工作目录一致。完整重跑还需要原始 EXE、分析中间产物及本机环境，不能只克隆仓库就完整运行。
`python -m unittest test_recovery -v` 的原生交叉校验依赖未纳入 Git 的 section 转储；现有运行结果见 `native_recovered/test_report.txt`。
已验证全部 4,106 个内层字段回加密一致。

没有启动原 EXE、执行恢复的宏或连接样本内置服务器。恢复的脚本可能操作键鼠和进程，不应未经审查执行。
原始 EXE、宿主系统 DLL 内存检查点、工具安装目录及临时转储均未纳入 Git。
Release 中的重建 PE 仅供分析，入口点为零，不是可运行的脱壳程序。

## 来源与许可

恢复内容、重建的分析工具与公开上游参考是不同来源，不应视为同一套原始源码。
上游参考固定在 `ChiyukiGana/Quickinput` 的 `f10b30b5b8785e275aec7eb60c994ce57eb542cf`，仅作为对照；原许可及第三方说明保留在参考归档中。
本仓库不为第三方内容重新授予许可。
