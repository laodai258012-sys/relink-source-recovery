# 上游参考源码来源

仓库：ChiyukiGana/Quickinput（GitHub）。
固定提交：f10b30b5b8785e275aec7eb60c994ce57eb542cf。

upstream_quickinput_reference.zip 是该提交的 git archive，保留原目录与许可证。
它不是从 Relink EXE 逐文件提取的原工程，也不能代表该私有分支的完整源码。

使用它的目的：对照动作类型、TypePack 格式、AES 算法和自定义脚本解释器。
已发现当前上游缺少 Q_ENCRYPT 条件引用的 encrypt/encrypt.cpp；不能宣称直接可构建出本 EXE。
本次恢复的外层/内层加密逻辑见 extract_macro_source.py 和 decode_macro_actions.py，这两份是根据二进制重建的分析工具。

许可证：保留仓库自带 LICENSE 及各第三方组件原有许可说明。请分别检查适用范围。

