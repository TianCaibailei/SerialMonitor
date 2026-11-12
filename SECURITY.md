# 安全说明

## 报告漏洞

请通过私有渠道联系维护者，**不要**先开公开 issue。请描述：
影响面（本程序 / 被注入进程 / 内核驱动）、复现步骤、期望行为与实测行为。

## 敏感材料管理

### 签名证书（重要）

内核驱动需要代码签名。本仓库**不包含**任何签名私钥：

- `driver/umfilter-test.pfx`（含私钥的测试证书）已从版本库移除，并由 `.gitignore` 阻止再次提交。
- 编译好的 `*.sys` 属于构建产物，同样不入库。

如果你克隆了较早的提交并发现历史里存在 `.pfx`，请**视为已泄露**：该测试证书只用于本机
加载未签名驱动，仍应立即作废并重新生成：

```powershell
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=umfilter-test" `
    -CertStoreLocation Cert:\CurrentUser\My
Export-PfxCertificate -Cert <thumbprint> -FilePath driver\umfilter-test.pfx `
    -Password (Read-Host -AsSecureString)
```

生产分发必须使用你自己的、由受信 CA 签发的证书（或走 WHQL），不要复用测试证书。

### 会话文件

`.umses` 会话存档保存的是**原始通信字节**，可能包含口令、密钥、个人数据。
它默认被 `.gitignore` 排除；分享前请自行审阅内容。

## 权限边界

| 组件 | 所需权限 | 风险 |
|---|---|---|
| 用户态注入（hook DLL） | 与被监控进程相同 | DLL 缺陷可能导致目标进程崩溃 |
| 内核过滤驱动 | 管理员 + 测试签名 | 驱动缺陷可能导致蓝屏 |
| 驱动控制接口 | 管理员 | 用每次启动生成的会话密钥鉴权，普通进程无法驱动 |

驱动只镜像 IRP、从不打开串口，因此不会抢占业务程序对端口的占用。
