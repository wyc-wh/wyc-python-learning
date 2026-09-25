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

## www.dihuangbox.com（补天公益 SRC，cid=65452 厂商：上海遥增智能）

- **2026-09-25 首轮匿名只读：无可提交漏洞**。静态 coolsite 建站模板官网
  （page1/2/9），无 catch-all / 无目录列表（403）/ 后台×4 与敏感文件×3 全 404 /
  无任何 Set-Cookie / nginx 无版本号 → R005/R013 版本面无证据可取
- R009「泛微 OA」= 引擎误报：`E-Mobile` 被 `apple-mobile-web-app` 子串命中
  → stacks.json weaver 指纹加 `\b` 词边界（规则靶场 25/25 回归过）
- R003 明文 HTTP 200 = 事实成立但**无链**（无会话 Cookie / R001 干净 / 纯静态）
  → 维持 detected 不提交（D-01）
- ⚠️ **归属主体不一致**：站点版权 = 上海递煌智能科技有限公司（沪ICP备20004178号-1~-4），
  补天项目厂商名 = 上海遥增智能 —— 提交时并列出示，被质疑再补关联证明
- 关联域名 `diyibox.com`（页脚邮箱）：未公开链出，范围外仅记线索
- 会话：BUTIAN-GY-65452-20260925-164716；报告 report_dihuangbox_20260925.md
- 唯一推进方向：厂商在补天明确业务系统资产范围 + 提供测试账号



## jxnu.edu.cn（补天公益 SRC，江西师范大学）

- **2026-09-25 首轮：4 条 confirmed 可提交** —— jwc（ASP.NET_SessionId 无 Secure）/
  oas（JSESSIONID）/ tsg（7 Cookie 全无 Secure）各 低危 3.1；
  mail（HTTP 明文下发 Coremail 登录表单、仅客户端 JS 升级）中危 4.2
- graduate（无 Cookie 纯静态）建议不提交；mail R014 twilio 特征 3 次复测不可复现 → 疑似误报
- 引擎误报两连修：R009 weaver 子串（dihuangbox）+ R001 占位符黑名单误杀
  XPCDP 合法值 `none`（改为合法值校验先行，靶场 25/25）
- 28 存活子域核查 10 个；uis=OpenResty 1.15.8.1（KB 无命中）；www/uis/vpn/pan/szqhjs 零发现
- 会话 BUTIAN-GY-JXNU-20260925-182944；**auth_id=占位值，提交前补真实 cid**
- 教训：verify --rule 整组升级会把最后一次 evidence 套到同组全部条目 → 提交稿逐条核对
- 提交侧待人工补：②归属 ICP ③首页截图 ⑤爱站权重 ⑥活动任务

**12 个靶场 728 条全绿**：6 + 37 + 81 + 25 + 20 + 44 + 36 + 57 + 80 + 67 + 40 + 235
（authgate / evidence_lint / coverage / rules / stack / authz / api_surface /
service_version / p1 / closure / fp / webui）

- webui 靶场演进：39（接入规则引擎前）→ **122**（UI 第一轮）→ **188**（UI 第二轮）
  → **193**（UI 简化 A）→ **211**（UI 第三轮方案 B+C）→ **218**（方案 D 门禁卡瘦身）
  → **221**（方案 E+F：说明压缩 + 流程节点纯状态）→ **235**（Dashboard 重构：视图切换 + 概览 7 卡）
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
