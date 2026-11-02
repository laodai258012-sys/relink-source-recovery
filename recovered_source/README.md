# 已恢复的宏源码（2026-11-02）

本目录来自 EXE 中唯一的 EMACRO 资源，不是从网上下载的替代脚本。

## 先看这些文件

- macro.readable.json：全部字段解密后的完整宏，包括界面、初始化脚本、两条分支、禁用动作。
- actions.readable.txt：全部 2,281 个动作的可读树，保留嵌套、条件与跳转。
- scripts/0000.qiml：原始界面定义，UTF-8。
- scripts/0001.txt：原始初始化脚本，UTF-8。
- action_scripts/：去重后的 1,012 个脚本/条件文本；action_script_manifest.json 记录全部 1,393 处使用位置。
- macro.full.json：外层解密后的原始字段结构，不替换混淆字段名。
- macro.decrypted.qim：外层解密得到的原始 TypePack 数据，335,611 字节。
- inner_fields.json：全部 4,106 个内层字段的解密记录。
- extraction_manifest.json / inner_verification.json：可复核的校验结果。

## 完整性与范围

外层 TypePack 335,611 字节全部消费，无剩余尾部；重新加密后与原始 335,616 字节资源完全一致。
内层 2,281 个类型、432 个备注、808 个脚本、585 个条件全部成功解密，逐项回加密完全一致。
禁用动作仍保留，没有按当前设置删除任何分支。field_map.json 是分析时采用的可读别名，不改变原始字段。
这里的“全部”仅指这个嵌入宏资源，不表示原生 EXE 的 C++、Qt、驱动或服务端源码已全部恢复。

## 复现

在原工作目录安装 pycryptodome 后运行：

    python extract_macro_source.py
    python decode_macro_actions.py

两份提取脚本随压缩包附带。它们仅处理文件数据，不执行宏、不启动样本、不连接内置网址。
恢复的脚本使用原软件的自定义脚本语言；它们不是 Python，也不能当作独立程序直接运行。
代码可能包含键鼠操作、进程管理、网址等功能，请勿未经审查执行。

## 与原生源码的区别

本目录恢复的是原始可读业务文本和序列化动作。反编译的 C/C++ 是另一种近似恢复，无法保证还原原始变量名、注释、项目结构或编译工程。
公开 Quickinput 仓库只是相关上游参考，不是本 EXE 私有修改版的完整源工程。

