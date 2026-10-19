# 签名自动更新

应用内更新使用两份文件：

- `personal.json`：更新清单（原始字节会被签名）
- `personal.json.sig`：证书与签名

## 1. 清单格式

```json
{
  "sku": "personal",
  "version": "1.1.1",
  "url": "https://github.com/your-org/your-repo/releases/download/v1.1.1/GhostProxifier-1.1.1-win64.zip",
  "size": 123456789,
  "sha256": "64 位小写十六进制",
  "notesUrl": "https://github.com/your-org/your-repo/releases/tag/v1.1.1"
}
```

- `sku` 必须与客户端的 `general.updateSku` 一致（默认 `personal`）。
- `version` 为 `x.y.z`，必须大于当前版本才会提示更新。
- `size` 与实际文件大小必须一致，范围 1 字节 ~ 500 MB。
- `sha256` 必须与实际文件一致，小写十六进制。
- `url`：
  - 生产环境必须 **HTTPS**，且必须命中 `general.updateAllowedPrefixes` 中的前缀（默认只允许 `https://github.com/`；可在 `config.json` 中扩展）。
  - 本地测试可使用 `file:///` 或绝对路径；此时清单也必须来自本地路径。

## 2. 签名格式

```json
{
  "cert": "<应用证书 DER 的 base64>",
  "certSig": "<根私钥对证书 DER 的 ECDSA-SHA256 签名 base64>",
  "sig": "<应用私钥对 personal.json 原始字节的 ECDSA-SHA256 签名 base64>"
}
```

客户端校验顺序：

1. 用编译进程序的根公钥验证 `certSig`（证书确实由根证书签发）。
2. 检查证书有效期；检查 `general.revokedCerts` 中的 SHA-256 指纹。
3. 用证书公钥验证 `personal.json` 原始字节的 `sig`。
4. 校验 SKU、版本、URL 前缀、大小、SHA-256。
5. 下载后再次校验大小与 SHA-256；全部通过才安装。

任何一步失败都会拒绝整份清单，不会提示下载。

## 3. 密钥与证书

当前工作区包含演示密钥：

| 文件 | 用途 |
| --- | --- |
| `root-key.pem` | 根私钥（只用于签发应用证书，**绝不要随程序分发**） |
| `root-cert.pem` | 根证书 |
| `root.pub.pem` | 根公钥（复制为 `app/update-root.pub.pem` 编译进程序） |
| `app-key.pem` | 应用签名私钥（只用于签发清单，**绝不要随程序分发**） |
| `app-cert.der` | 应用证书 DER（放进 `.sig` 的 `cert`） |
| `app-cert.pem` | 应用证书 PEM（便于查看） |

重新生成（OpenSSL）：

```bash
openssl ecparam -name prime256v1 -genkey -noout -out update/root-key.pem
openssl req -new -x509 -key update/root-key.pem -days 3650 -sha256 \
  -subj "/CN=My Update Root" -out update/root-cert.pem
openssl ec -in update/root-key.pem -pubout -out update/root.pub.pem

openssl ecparam -name prime256v1 -genkey -noout -out update/app-key.pem
openssl req -new -key update/app-key.pem -subj "/CN=My Update Signing" -out update/app.csr
openssl x509 -req -in update/app.csr -CA update/root-cert.pem -CAkey update/root-key.pem \
  -CAcreateserial -days 3650 -sha256 -out update/app-cert.pem
openssl x509 -in update/app-cert.pem -outform der -out update/app-cert.der

cp update/root.pub.pem app/update-root.pub.pem
```

## 4. 签名与发布

```bash
node tools/sign-update.js update/personal.json
```

将 `personal.json` 与 `personal.json.sig` 原样发布到清单 URL 和 `<清单 URL>.sig`。**不要重新序列化清单**——签名针对原始字节；编辑器自动补换行/改编码都会让签名失效。

## 5. 更新包格式

推荐 ZIP，内容应为**便携版目录的内容本身**（不要把外层文件夹打进去）：

```
GhostProxifier.exe
resources/
  native/
  app.asar
  licenses/
*.dll / *.pak / locales/ ...
```

客户端会启动一个 PowerShell 脚本：等待当前进程退出 → `Expand-Archive -Force` 到程序目录 → 重新启动 exe。也可使用 `.msi`，客户端调用 `msiexec /i <file> /passive /norestart`。

## 6. 配置

在 `%APPDATA%\ghost-proxifier-replica\config.json` 中：

```json
{
  "general": {
    "updateUrl": "https://your.host/update/personal.json",
    "autoCheckUpdates": true,
    "updateSku": "personal",
    "updateAllowedPrefixes": ["https://github.com/", "https://your.host/"],
    "revokedCerts": []
  }
}
```

设置 → 关于 中也可以填写更新清单 URL 与自动检查开关。

## 7. 示例文件

`personal.json` / `personal.json.sig` / `test-package.zip` 是本地验签测试样例（版本 1.1.1，指向一个 200 字节的测试 ZIP）。**不要把示例清单当作正式更新源**；安装它不会得到完整程序。正式发布请用真实便携版 ZIP 重新生成清单并签名。
