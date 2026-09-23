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

**12 个靶场 681 条全绿**：6 + 37 + 81 + 25 + 20 + 44 + 36 + 57 + 80 + 67 + 40 + 188
（authgate / evidence_lint / coverage / rules / stack / authz / api_surface /
service_version / p1 / closure / fp / webui）

- webui 靶场演进：39（接入规则引擎前）→ **122**（UI 第一轮）→ **188**（UI 第二轮）→ **193**（UI 简化 A）
- 跑法：`PENTEST_NODE=<node.exe> python _test_*.py`；**node 缺失时 webui 的前端 JS
  语法闸会显式 SKIP 且不计入通过**（虚门禁比没门禁更危险），故设了才拿到 188

## 待办（优先级降序）

1. 提交回执闭环（比挖新洞更重要）
2. ikuai8 的 `demo.` / `icc.` 登录态验证
3. **修 `target_in_scope` 两处实现不一致**：`orchestrator` 版**不**剥端口 /
   `rules_engine` 版会剥 → 带端口的 target 在 init 与 check 两侧判定相反，
   coverage 的 `hosts_missing` 会把已核查的 `host:port` 误报为缺失。
   **动它要改 coverage 读数语义，需单独评估**
4. **Web 端仍未接** `fp_review`（驳回风险预演）与 `credentials`（登录态）——
   规则引擎 / lint / coverage 已于 2026-09-23 接入（②卡片）
5. XBEN 外部基准（只读方法学下分数会极低，但这本身把「合规代价」量化出来）
