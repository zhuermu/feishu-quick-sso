# Amazon Quick 快速上手指南

> 一页纸搞定：下载 → 登录 → MCP 配置

---

## 1️⃣ 下载安装

| 平台 | 操作 |
|------|------|
| macOS / Windows | 访问 **https://quick.aws.com/** → 下载对应平台客户端 → 安装 |

---

## 2️⃣ 登录（⚠️ 首次需要登录两次）

### Step 1：打开客户端，选择企业 SSO 登录

选择 Region（推荐 Dynamic），点击 **"Continue with SSO"**：

![选择企业SSO登录](artifacts/login_step1_sso.jpg)

### Step 2：浏览器中输入企业账户名称

首次点击后会跳转到浏览器，输入管理员提供的 **Quick 账户名称**，点击"下一个"：

![输入企业账户名称](artifacts/login_step2_account.jpg)

### Step 3：完成两次授权

| 步骤 | 说明 |
|------|------|
| **第一次授权** | 完成企业 SSO 认证后，会跳转到 **Quick Web 版本**（这是正常现象） |
| **第二次授权** | 回到 **Quick 桌面端**，再次点击 **"Continue with SSO"**，此次授权后将正常进入桌面客户端 |

> 💡 **提示**：后续使用只需一次登录即可直接进入桌面端。

---

## 3️⃣ MCP 配置（以飞书 Lark CLI 为例）

### 前置准备

1. 确保已安装 **Node.js**（v18+）
2. 准备好飞书应用的 `APPID` 和 `AppSecret`

### 配置步骤

1. 打开 Quick 桌面端 → **Settings** → **Capabilities** → **Connections**
2. 点击 **"+ Add"** → 选择 **MCP**
3. 填写配置信息：

```json
{
  "name": "lark-cli-mcp",
  "command": "npx",
  "args": ["-y", "@anthropic/lark-cli-mcp"],
  "env": {
    "APPID": "<你的飞书应用 APPID>",
    "APP_SECRET": "<你的飞书应用 AppSecret>"
  }
}
```

> 📖 详细配置参考：**https://github.com/zhuermu/lark-cli-mcp**

4. 保存后，在对话中即可使用飞书相关能力（发消息、查日历、读文档等）

---

## ✅ 验证

在 Quick 中输入以下内容测试：

```
帮我查看飞书上的最近消息
```

如果返回消息列表，说明配置成功 🎉

---

*更多功能探索：直接在 Quick 中描述你想做的事情，它会自动调用合适的工具。*
