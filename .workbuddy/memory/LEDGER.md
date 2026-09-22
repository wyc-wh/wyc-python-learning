# 台账 - 授权目标进展（从 MEMORY.md 拆出）

> 这里放**易变的项目状态**（目标进展、待办、回归基线），不放硬规则。
> 硬规则见 `MEMORY.md`，方法论详情见 `HANDBOOK.md`。

## ikuai8.com（补天公益 SRC）

- **F-10 高危**：Discuz! X3.3 EOL + 登录失败计数失效，7.4 / 7.7（可提交）
- F-05 中危 6.5；F-11（admin.php 明文 HTTP 5.9）降级为 F-10 的加重情节，不单独成单
- R012 试跑 8 个 in_scope 资产，未命中未授权访问
- `demo.` / `icc.` 的 SPA bundle 匿名可下载（各自提取出 `/fs/*`、`/admin/index/*`、`/console/*` 清单），
  但匿名请求被 catch-all 兜回首页 / 404 → **需登录态才能验证鉴权**（待办）
- `bbs` 的 `/.env`、`/.git/config` 均返 **405/1841B**（阿里云边缘节点统一错误页）
  → 路径是否存在未判定，**别再重复试探**
- 归属证明已命令行取证（论坛页脚 `京ICP备13042604号` = 官网同主体）
  → 浏览器侧待办只剩「首页截图含地址栏」+「爱站权重」

## jiaoyu.cn（补天公益 SRC）

- **J-01 中危**：qmt 安全头占位符失效，6.8 / 6.4
- 11 资产全重跑（覆盖 100 / A）无高危，**匿名侧确实扎实**；报告 §0 已诚实写明
- 登录态（R010 / R011）因无 Cookie 未覆盖 —— **唯一可能翻高危的方向**
- **⚠️ jiaoyu 的 SPA bundle 全在认证墙后**（登录页是纯静态「无权限页面」0 个 script，
  404 也 302 回 login）→「从 bundle 捞 API 清单」对该站无效，**勿重复尝试**。
  要挖只能靠登录 Cookie（**2 小时过期**，`laravel_session` + `XSRF-TOKEN` 缺一不可，
  三个子站不通用）

## 回归基线

**11 个靶场 493 条全绿**：6 + 37 + 81 + 25 + 20 + 44 + 36 + 57 + 80 + 67 + 40
（authgate / evidence_lint / coverage / rules / stack / authz / api_surface /
service_version / p1 / closure / fp）

## 待办（优先级降序）

1. 提交回执闭环（比挖新洞更重要）
2. ikuai8 的 `demo.` / `icc.` 登录态验证
3. **Web 界面接入只读规则引擎**：`webui.py` 仍是 v0.5 基线版，
   无 `/api/check` → R001~R014 / lint / coverage / fp_review / credentials
   在 Web 端完全不可用（只能走 CLI）。2026-09-23 已修其 scan 分支的
   `payload` 未定义必崩点，但「前端与能力脱节」本身未解决
4. XBEN 外部基准（只读方法学下分数会极低，但这本身把「合规代价」量化出来）
