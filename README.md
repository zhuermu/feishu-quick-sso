> ⚠️ **本仓库已迁移**
> 最新代码与文档请移步 → **[aws-samples/sample-for-amazon-quick-sso-with-feishu](https://github.com/aws-samples/sample-for-amazon-quick-sso-with-feishu)**
> 本仓库不再更新，仅作历史存档。

# 飞书 × Amazon Quick 单点登录

用**飞书自建应用**作为唯一身份源，让
[Amazon Quick Web](https://docs.aws.amazon.com/quick/latest/userguide/identity.html) 和
[Amazon Quick Desktop](https://docs.aws.amazon.com/quick/latest/userguide/amazon-quick-desktop.html)
都用飞书登录。适合**没有现成企业 IdP**（Entra ID / Okta 等）的组织。

全 Serverless，**无数据库、无常驻服务器**：两个 Lambda + API Gateway、一个 Cognito User Pool、
一个 KMS 密钥、一个 IAM 角色。

> 📖 完整部署操作步骤见 [`docs/飞书-Quick-统一登录部署手册.md`](docs/飞书-Quick-统一登录部署手册.md)。

## 架构

```
                         浏览器里的一次飞书登录
                                  │
                   ┌──────────────▼───────────────┐
                   │   Cognito User Pool           │  ◄── 唯一身份源
                   │   + 飞书 OIDC 适配器 (联邦 IdP) │
                   └──────┬────────────────┬───────┘
             OIDC (PKCE)  │                │  OIDC 授权码流
                  ┌───────▼──────┐  ┌──────▼─────────────────────┐
                  │ Quick Desktop│  │ Web 登录门户 (Lambda)        │
                  │ 经剥离代理    │  │ 验 id_token → 取 email      │
                  └──────────────┘  │ AssumeRole (Email 标签)     │
                                    │ getSigninToken → 302 Quick  │
                                    └────────────────────────────┘
```

- **飞书 OIDC 适配器**（`lambda/feishu_oidc_adapter`）：Cognito 联邦的上游 IdP。把飞书
  `/authorize` 代理到飞书、用 code 换 `user_access_token`、读 `/user_info`、用 KMS RSA 密钥签
  `id_token`（JWKS 由 `kms:GetPublicKey` 导出，私钥不出 KMS）。另内置 `/cognito/*` 剥离代理，
  去掉 Quick Desktop 强发的 `offline_access`（Cognito 不支持该 scope）后转发给 Cognito。
  `/user_info` 取不到邮箱时（如用户只在通讯录配了企业邮箱），自动用 tenant_access_token 调
  通讯录 API 兜底。
- **Web 登录门户**（`lambda/web_portal`）：对同一个 Cognito Pool 跑 OIDC 授权码流，取到 `email`
  后用 `sts:AssumeRole`（打 `Email` 会话标签）+ AWS 联邦端点换取 Quick Web 登录会话。

## 单点登录原理

SSO 靠的是**共享 IdP 处的浏览器会话**，不是共享 token。登录任一侧后，浏览器留有飞书/Cognito
会话 cookie；在 Quick Desktop 内点 **More → Chat agents** 等 Web 深链接时复用该会话，无需二次认证。

## 前提

- **飞书自建应用**：开通并发布 `contact:user.email:readonly` 和 `contact:user.employee:readonly`
  权限；可用范围覆盖使用 Quick 的成员；记下 App ID（`cli_xxxx`）和 App Secret。
- **Amazon Quick Enterprise** 账户，采用 **IAM federation** 认证，区域 **us-east-1**。
- Node 18+、Python 3.12、AWS CDK v2、目标账号的 AWS 凭证。

## 部署

```bash
npm install
npx cdk bootstrap                              # 每个账号/区域一次
npx cdk deploy -c feishuAppId=cli_xxxxxxxxxxxx
```

写入飞书 App Secret（不进代码、不进 CDK context）：

```bash
python3 scripts/set_feishu_secret.py --app-secret <FEISHU_APP_SECRET>
```

冒烟测试：

```bash
python3 scripts/verify_deployment.py
```

之后按手册配置 Quick Desktop extension 与 Quick Web 登录。

## 部署参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `-c feishuAppId=cli_xxxx` | *（必填）* | 飞书自建应用 App ID |
| `-c lark=true` | `false` | 用 Lark（larksuite.com）端点 |
| `-c subjectClaim=open_id` | `union_id` | OIDC `sub` 用哪个飞书 id |
| `-c emailClaim=work` | `enterprise` | 邮箱取值：`enterprise`（企业优先）/`work`（工作优先）/`enterprise_only`/`work_only` |
| `-c quickRegion=us-east-1` | 部署区域 | Quick 所在区域 |
| `-c allowedCidrs='["1.2.3.0/24"]'` | *（开放）* | 限制两个 API Gateway 的来源 IP |
| `-c retain=true` | `false` | 删栈时保留 User Pool / KMS 密钥 |

## 安全须知

- **KMS 签名密钥**：适配器用非对称 KMS 密钥签 `id_token`，私钥不出 KMS。删栈会计划删除该密钥，
  除非 `-c retain=true`。
- **API Gateway 默认公开**：用 `-c allowedCidrs` 加资源策略限制来源 IP，或给 `prod` stage 挂 AWS WAF。
- **联邦角色权限**：Quick 联邦角色默认授予 `quicksight:*`，建议按最小权限收敛（信任策略已限定为门户
  Lambda 角色）。
- **`sub` 选择不可逆**：默认 `union_id`（换飞书应用后身份稳定）；`open_id` 仅应用内唯一，改动会重新
  预置所有用户。
- **会话时长**：门户经角色链 AssumeRole，会话上限 1 小时；到期后只要飞书浏览器会话在，重新进门户
  会静默续期。
- **离职回收**：Cognito refresh token 有效期内不回飞书校验，离职时应缩短有效期或禁用 Cognito 用户。
