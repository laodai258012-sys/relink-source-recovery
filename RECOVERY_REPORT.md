# Relink 源码提取总包

## 结果与边界

- 嵌入宏：完整恢复 2,281 个动作、808 处脚本、585 处条件、432 个备注、界面定义及初始化脚本。
- 外层 335,611 字节完整解析；所有 4,106 个内层字段重新加密后均与输入一致。
- 原生程序：异常表列出的 105,280 个地址范围全部完成反编译尝试，其中 105,234 个成功生成 C 风格伪代码，46 个未成功，失败清单逐项列出。
- 全部 105,280 个异常表范围均另有反汇编，无论 C 伪代码是否成功。
- 另外通过直接调用/跳转和静态代码指针找到 13,615 个不在异常表内的叶函数/跳板候选，已全部尝试，其中 13,611 个生成伪代码；候选身份不保证等于独立源函数。
- 资源编辑器：430 个异常表函数全部生成伪代码。
- 另有重建的 x86 重启助手 C 文件、22 项程序资源及公开上游参考源码。

这些结果不是原作者可直接重新编译的完整 C++ 工程。函数名、类型、变量名和控制流可能是反编译器推断；注释、原始源文件划分、项目配置及服务端源码无法从本 EXE 自动恢复。
异常表记录也可能是函数片段，并不等于原始源函数数量；无展开记录的叶函数不一定在该列表中。完整 .text 字节保留在 analysis.pe 中。

## 目录

- recovered_source/：首先查看 README.md、macro.readable.json、actions.readable.txt，以及 scripts/、action_scripts/。
- native_recovered/all_native_pseudocode.zip：全部成功导出的主程序和资源编辑器 C 伪代码，文件名为 RVA。
- native_recovered/all_functions_assembly.zip：全部异常表记录对应的反汇编和地址索引。
- native_recovered/leaf_candidates_assembly.zip：额外候选范围的反汇编；unclassified_text.zip 另保留其余代码区字节（可能是填充、数据表或未识别代码），没有把它们隐藏或算作已恢复源码。
- native_recovered/reconstructed.analysis.pe：仅供静态分析的重建 PE；入口点刻意设为零，不能当成脱壳可运行程序。
- native_recovered/decompile_failures.json：C 伪代码失败记录，对应机器码仍在反汇编/PE 中。
- recovered_assets.zip：模型、字典、配置、图片、音频和原始加密宏等资源。
- recovered_helper/：重建的小型 x86 助手 C 源码与说明。
- upstream_reference/：固定提交的 Quickinput 上游，只用于参考，不冒充本 EXE 私有分支源码。
- tools/：提取、解密、核验及反编译脚本；运行完整链路需要原 EXE、对应依赖和原工作目录结构。

## 安全与复现

未启动原 EXE，也未执行宏；保护层通过受限 CPU 模拟恢复，系统 API 由内存模型替代。未连接程序内置服务器。
不分发包含宿主系统 DLL 内存的模拟检查点。分析 PE 的导入表采用模型导出名重建，可能与原别名不同。
工具脚本是本次重建的分析代码，不是原程序作者源码。依赖版本见 tools/requirements-recovery.txt，Ghidra 使用 11.0.3 / JDK 17。
测试包含 TypePack 边界条件、已知明文、完整宏校验及 XOR 算法与原生机器码的独立交叉校验。
原文件 SHA256：15405f1cd736f38ee315469e0b3eeddb87fd179103dc642acadd9440ccc6e696。
