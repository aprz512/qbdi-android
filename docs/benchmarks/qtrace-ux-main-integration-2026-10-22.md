# handoff 本地 main 合入与复核

日期：2026-10-22。用户已授权先合入 main，再独立调查赛马娘拒绝原因与远端上报。**handoff 实现已本地快进合入 main，合入后回归通过。** 未推送，未删除分支或工作树。

- 原 main 与任务分支基线均为 `eb79bcb2c37acb27affda4983ecb099e3ac5c497`，合入前 main 干净。
- 实现提交为 `2bd271f1f360dc69e337ba8b3a57470f321b511c`，共 89 个文件，包含功能、测试、文档、筛选后的验收及研究证据。
- 合入使用 `git merge --ff-only feat/qtrace-ux-handoff`，没有冲突或源码合并改写。
- 合入前核对 389 个源码文件，与已通过设备门禁的候选字节一致；八个场景报告、成功 manifest 及主机检查日志 SHA 均匹配。
- 合入后在 `/home/lyldalek/workspace/qbdi-android` 重跑 Python 全量：963 项，9 项跳过，无失败。
- 合入后重跑 `check_protocol_matrix.py --check --skip-rust`：生产 C++ encoder、Python 读取、fixture 字节与 16 项协议测试通过。本次没有重跑 Rust；原 524 passed / 2 ignored、50 项 native、Debug/Release 构建及设备门禁按未改变的源码输入复用。

[机器证据](evidence/qtrace-ux-main-integration-2026-10-22.json)保存提交、实现 tree、命令、日志 SHA 与原门禁身份。[原始完整验收](qtrace-ux-remaining-2026-10-22.md)继续绑定实际采集时的基线和产物，不改写成新设备运行。

本次合入及主机复核没有操作设备。既有 Pixel 6 / Mi 11 恢复报告均为 pass、cleanup=true，原始报告已核对保存。`cd7b` 的 `out/`、原始门禁目录及 `6580` 的原始调查材料继续保留；研究文档的本机原始资料链接固定指向实际存放路径。

后续调查从合入后的 main 建立独立研究分支。实际检测命中、物理拒绝根因和远端上报仍按[补证报告](../research/2026-10-22-umamusume-verification.md)的缺口取证，不作为未完成的 handoff 功能，也不把游戏标题页或工具通过升级为这些结论。
