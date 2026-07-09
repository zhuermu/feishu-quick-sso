# 飞书 × Amazon Quick 单点登录部署手册

用飞书自建应用作为身份源，让 Quick Web 和 Quick Desktop 用飞书登录。按以下步骤操作。

> 前提：Amazon Quick Enterprise 账户，区域 **us-east-1**，认证方式为
> **Password-based or Single-Sign On**；本机装好 Node 18+、Python 3.12、AWS CDK v2 及 AWS 凭证。

---

## 1. 创建飞书自建应用

1. [飞书开放平台](https://open.feishu.cn/) → 开发者后台 → **创建企业自建应用**。
2. **凭证与基础信息** 页记下 **App ID**（`cli_` 开头）和 **App Secret**。
3. **权限管理** → 开通：
   - `获取用户邮箱信息`（`contact:user.email:readonly`）
   - `获取用户受雇信息`（`contact:user.employee:readonly`）— 读通讯录里的企业邮箱兜底用
4. **可用范围** → 设为使用 Quick 的部门/成员。范围内用户须在通讯录里有邮箱（企业邮箱或工作邮箱皆可，
   见下方 `emailClaim` 参数），且与 Quick 用户邮箱一致。
   - 用户若只在**通讯录**里配了企业邮箱（未在飞书个人设置绑定），适配器会自动用通讯录 API 兜底取到，
     无需用户自己绑定。
5. **重定向 URL** 先留空（第 3 步回填）。
6. **创建版本并发布**（权限和可用范围改动必须发布才生效）。

> 海外 Lark 租户：部署时加 `-c lark=true`。

---

## 2. 部署 CDK 栈

```bash
cd feishu-quick-sso
npm install
npx cdk bootstrap                                  # 每个账号/区域一次
npx cdk deploy -c feishuAppId=cli_xxxxxxxxxxxx     # 用你的 App ID
```

记下输出（`Outputs`）：

| 输出键 | 用途 |
|--------|------|
| `FeishuRedirectUri` | 回填飞书应用的重定向 URL |
| `DesktopIssuerUrl` / `DesktopClientId` / `DesktopAuthEndpoint` / `DesktopTokenEndpoint` / `DesktopJwksUri` | 配置 Quick Desktop extension |
| `WebPortalLoginUrl` | Quick Web 门户地址（第 5 步用） |
| `FederationRoleArn` | 联邦角色 |

---

## 3. 回填重定向 URL 并写入 App Secret

1. 把 `FeishuRedirectUri`（`https://.../prod/callback`）填进飞书应用 **安全设置 → 重定向 URL**，保存。
2. 写入 App Secret：
   ```bash
   python3 scripts/set_feishu_secret.py --app-secret <FEISHU_APP_SECRET>
   ```
3. 冒烟测试，全部 `PASS` 再继续：
   ```bash
   python3 scripts/verify_deployment.py
   ```

---

## 4. 配置 Quick Desktop extension

在 **Quick 管理控制台 → Extensions** 配置（不是在桌面 App 里）：

1. **Extension access** → 填入下列 6 项（取自第 2 步输出）：

   | 字段 | 取值 |
   |------|------|
   | Issuer URL | `DesktopIssuerUrl` |
   | Client ID | `DesktopClientId` |
   | Authorization endpoint | `DesktopAuthEndpoint`（`.../prod/cognito/authorize`） |
   | Token endpoint | `DesktopTokenEndpoint`（`.../prod/cognito/token`） |
   | JWKS URI | `DesktopJwksUri` |
   | Redirect URI | `http://localhost:18080` |

   > Auth/Token 端点照抄栈输出（`/cognito/*`），不要改成 Cognito 域直连。

2. **Extensions 页 → Add extension** → 选中上面的 access → **Create**。（只加 access 不 Create，Desktop 无法登录。）
3. **从 Extensions 页重新下载桌面应用** 并安装（Create 之后下载的构建才带 SSO）。

---

## 5. 配置 Quick Web 登录

**Quick 管理控制台 → Single sign-on (IAM federation)**：

1. **Email Syncing for Federated Users** → **ON**。
2. **Service Provider Initiated SSO** → **ON**，填：
   ```
   IdP URL:  <WebPortalLoginUrl>
   ```
   （必须开：否则 Quick Desktop 发起的登录会落到 Quick Web 原生登录页，无法跳飞书。）
3. 联邦角色 `FederationRoleArn` 默认授予 `quicksight:*`，按需收敛。

---

## 6. 验证

1. **Desktop**：Quick Desktop → Continue with SSO → 飞书授权 → 登录成功。（首次若卡在等待跳转，重新发起一次。）
2. **Web**：访问 Quick 网址 → 自动跳飞书 → 进 Quick Web。
3. **深度集成**：Desktop 登录后点 **More → Chat agents**，应直接打开 Web 内容，无需重新登录。

---

## 7. 常见问题

| 现象 | 处理 |
|------|------|
| `feishu user has no email` | 未发布 `contact:user.email:readonly` + `contact:user.employee:readonly` 权限，或用户在通讯录没填任何邮箱，或应用可用范围不含该用户 |
| Desktop 报 `invalid_scope` | Auth/Token 端点直连了 Cognito，改用 `/cognito/*` 端点 |
| 用户不在可用范围 | 飞书后台把可用范围设为使用 Quick 的部门/成员 |
| 换了飞书应用后 /token 失败 | 新 App Secret 不同，重跑 `set_feishu_secret.py` |
| Quick 里重复用户 | 确认飞书邮箱与 Quick 用户邮箱完全一致，并开启 Email Syncing |
| 换飞书应用后用户身份延续 | 用默认 `subjectClaim=union_id`（`open_id` 仅应用内唯一） |

---

## 8. 部署参数

| 参数 | 说明 |
|------|------|
| `-c feishuAppId=cli_xxx` | 飞书 App ID（必填） |
| `-c lark=true` | 用 Lark（larksuite.com）端点 |
| `-c subjectClaim=open_id` | OIDC `sub` 用 open_id（默认 union_id） |
| `-c emailClaim=work` | 邮箱取值策略（默认 `enterprise` 企业邮箱优先）：`enterprise`=企业优先回退工作 / `work`=工作优先回退企业 / `enterprise_only` / `work_only`=只取该字段 |
| `-c quickRegion=us-east-1` | Quick 所在区域 |
| `-c allowedCidrs='["1.2.3.0/24"]'` | 限制 API Gateway 来源 IP |
| `-c retain=true` | 删栈时保留 User Pool / KMS 密钥 |
