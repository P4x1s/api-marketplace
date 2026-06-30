# AI API Marketplace

一个完整的AI API代理中转站系统，支持用户注册、API密钥管理、用量计费。

## 功能特性

- ✅ 用户注册/登录系统
- ✅ API密钥管理
- ✅ 余额充值与扣费
- ✅ 多模型支持（MIMO、GPT等）
- ✅ 用量统计

## 部署架构

- **前端**: Vercel (静态托管)
- **后端**: AWS Lambda + API Gateway
- **数据库**: AWS DynamoDB
- **AI模型**: MIMO API

## API端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/auth/register` | POST | 用户注册 |
| `/auth/login` | POST | 用户登录 |
| `/topup` | POST | 充值余额 |
| `/balance` | GET | 查询余额 |
| `/api-keys` | GET/POST | 管理API密钥 |
| `/chat/completions` | POST | 调用AI模型 |
| `/models` | GET | 获取模型列表 |

## 快速开始

### 1. 注册账号
```bash
curl -X POST https://your-api-endpoint/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword","name":"Your Name"}'
```

### 2. 登录获取Token
```bash
curl -X POST https://your-api-endpoint/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}'
```

### 3. 充值余额
```bash
curl -X POST https://your-api-endpoint/topup \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount":10}'
```

### 4. 调用AI模型
```bash
curl -X POST https://your-api-endpoint/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"mimo-v2.5","messages":[{"role":"user","content":"Hello"}]}'
```

## 支持的模型

- `mimo-v2.5` - MiMo v2.5
- `mimo-v2.5-pro` - MiMo v2.5 Pro
- `gpt-4` - GPT-4
- `gpt-3.5-turbo` - GPT-3.5 Turbo

## 定价建议

| 模型 | 价格 (每1K tokens) |
|------|-------------------|
| mimo-v2.5 | $0.002 |
| mimo-v2.5-pro | $0.01 |
| gpt-3.5-turbo | $0.002 |
| gpt-4 | $0.03 |

## 技术栈

- **前端**: HTML/CSS/JavaScript
- **后端**: AWS Lambda (Node.js)
- **数据库**: AWS DynamoDB
- **部署**: Vercel + AWS

## 许可证

MIT License
