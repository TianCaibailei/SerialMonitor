# 已知问题记录

## b652465 提交无法编译（历史遗留，不影响 HEAD）

**现象**：`git checkout b652465` 后 `cargo build` 报 6 个 E0609 错误
（`no field drv_cmd / drv_evt on type MonitorApp`）。

**原因**：多智能体并行开发时，Lead 执行 `git add -A` 把某个 agent 当时
只写了一半的 `ui.rs`（引用了尚未添加的字段）一并提交了。

**当前状态**：HEAD (4bcb820) 已完整，编译通过（Finished，0 error）。

**教训**：
- 多智能体并行时，提交前应确认所有 agent 的改动都处于自洽状态
- 不要在有 agent 正在写文件时用 `git add -A`
- 更好的做法：每个 agent 只提交自己的文件，或等其完成后再提交

**如需修复历史**：这个 commit 只是开发过程中的一个中间态，不用于发布，
无需 rebase 修复。若确实需要，可在该 commit 上补上字段定义后 `git commit --amend`
（但会重写后续所有 commit 的哈希，不推荐）。
