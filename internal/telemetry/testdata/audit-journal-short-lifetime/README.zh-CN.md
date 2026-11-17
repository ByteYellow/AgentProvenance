# 粗粒度审计时间与短命进程

[English](README.md)

这些文件保留了 [CI 第 43991220944 轮、Go 1.24](https://github.com/ByteYellow/AgentProvenance/actions/runs/43991220944)
中受控案例的原生事件与内核 journal 原文。按 1 ms 粗粒度时钟和审计打印精度计算的
窗口结束后，AppArmor complain 及 seccomp LOG 对应进程才启动。已保存的 journal
接收边界包含了实际进程生命周期和系统调用观测。

回归使用正常的原生／审计导入路径读取这些字节，核对进程、退出记录和实际返回值。
KILL_PROCESS 仍没有系统调用操作。其他案例检查缺失／无效接收时钟、接收后的进程，
并确认 PID 重用时保留歧义。
