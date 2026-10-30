# ZETA CYBERLAB — Reverse Engineering Assistant Prompt

> 一份开箱即用的**逆向工程 / 二进制分析专家 System Prompt**，用于把通用大模型（ChatGPT / Claude / DeepSeek / GLM / Gemini 等）配置为专业的软件逆向工程研究助手。

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-V5.0-blue.svg)](#)
[![Prompt](https://img.shields.io/badge/type-system--prompt-orange.svg)](#)

---

## ✨ 特性

- **12 个专业模块**：PE/ELF/Mach-O 文件结构、x86/ARM 汇编与反编译、动态调试、加壳/混淆/反调试研究、内存与运行时分析、授权设计审计、逆向工具链开发（Capstone / Unicorn / Frida / angr / LIEF / YARA / Ghidra API）。
- **自动化研究工作流**：识别 → 结构分析 → 静态分析 → 动态分析 → 逻辑还原 → 验证 → 报告，七步闭环。
- **标准化输出格式**：目标分析 / 技术原理 / 实现代码 / 运行方法 / 结果验证 / 异常排查，直接可用的技术报告结构。
- **研究诚信约束（防幻觉）**：强制不虚构反汇编结果、不伪造调试输出、推测与事实分离 —— 专门抑制大模型在逆向场景下的"编造 API / 编造偏移量"通病。
- **授权边界内建**：面向自有软件、授权软件、CTF 赛题与隔离实验环境，自动拒绝未授权的密钥提取与访问控制绕过。

## 📦 使用方法

1. 打开 [`ZETA-CYBERLAB-V5-prompt.md`](ZETA-CYBERLAB-V5-prompt.md)，全选复制全文。
2. 粘贴到模型的 System Prompt / 角色预设 / 自定义指令中（ChatGPT Custom Instructions、Claude Projects、DeepSeek 助手设定、SillyTavern 角色卡均可）。
3. 直接粘贴二进制分析任务（文件描述、反汇编片段、调试日志），助手会自动进入七步工作流并选择对应 Expert 模式。

## 🎯 适用人群

- CTF Reverse / Pwn 方向选手
- 软件安全研究员与漏洞分析工程师
- 需要维护自有程序补丁与兼容性的开发者
- 学习二进制安全课程的学生

## 🔍 关键词

`reverse engineering` `system prompt` `binary analysis` `PE` `ELF` `Mach-O` `x64dbg` `Ghidra` `IDA Pro` `Frida` `angr` `Capstone` `Unicorn` `CTF` `malware analysis` `software protection` `LLM prompt` `AI assistant` `逆向工程` `提示词` `二进制分析` `安全研究`

## ⚖️ 合规声明

本提示词仅用于**合法授权场景**：自有软件分析、已授权的安全评估、CTF 竞赛、隔离实验环境与防御性安全研究。使用者需自行遵守所在司法辖区的法律法规（如《计算机软件保护条例》、DMCA 等）及目标软件的许可协议。作者不对滥用行为负责。

## 📄 许可证

[MIT License](LICENSE)
