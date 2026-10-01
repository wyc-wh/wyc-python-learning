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

## lenovo.com.cn / motorola.com.cn（补天联想 SRC，含奖励计划）

- **2026-09-28 首轮匿名只读：终止在 recon+check，零可提交漏洞**。CT 203+13 子域 →
  21 主机探测存活主入口 6 个（www/support/app/sso/api/file）→ 规则引擎
  R001/R003/R006/R008/R009/R012/R013 全部 findings=[]；厚 CDN（EdgeOne/BigIP/
  istio-envoy），API 面全在认证墙后，R013 无版本证据（R005 未生效记待跟进）
- gitlab.mbgstore 公网 DNS 指向 10.192.10.118（RFC1918 泄露，同 jxnu ehall 判例：仅记录）
- 13 个 CT 主机 DNS 已死（证书残留，勿再探测）
- ⚠️ 授权缺口未补：cid 占位、截图 scope 疑截断、「禁止自动化扫描器」标注未核实
  → 提交闸 locked；深挖唯一方向 = 登录态（需测试账号）
- 会话：BUTIAN-LENOVO-20260928-194055；工件 rules_lenovo_*.json + _probe/_ct/_dns/_sanity
- **工程教训（当日日志详版）：heredoc 长命令回显渲染损坏 ×4 → 一切以落盘 + Read 通道为准**
- 唯一推进方向：厂商在补天明确业务系统资产范围 + 提供测试账号



## jxnu.edu.cn（补天公益 SRC，江西师范大学）

- **2026-09-25 首轮：4 条 confirmed 可提交** —— jwc（ASP.NET_SessionId 无 Secure）/
  oas（JSESSIONID）/ tsg（7 Cookie 全无 Secure）各 低危 3.1；
  mail（HTTP 明文下发 Coremail 登录表单、仅客户端 JS 升级）中危 4.2
- **2026-09-26 深挖：+1 条 confirmed（zsjy 招生就业院，低危 3.1）** —— 明文 200 不跳转
  且明文响应即下发 ASPSESSIONIDCSQABTSC（无 Secure/HttpOnly/SameSite），
  链比首轮三条更完整（已在审计链 verify）；提交稿条目数 5→6
- 深挖扩面：CT+DNS 新增 16 解析；6 个部门 CMS（rsc/cwc/kjc/tw/zzb/my）明文 302 无 Cookie
  → R003 测无发现；app/uniapp/portal-service catch-all 兜底无法判定；oa 502 后端挂；
  webvpn TLS `unrecognized name` 待换 SNI 复测；ehall/portal 公网 DNS 泄露私网地址（不提交）
- graduate（无 Cookie 纯静态）建议不提交；mail R014 twilio 特征 3 次复测不可复现 → 疑似误报
- 引擎误报两连修：R009 weaver 子串（dihuangbox）+ R001 占位符黑名单误杀
  XPCDP 合法值 `none`（改为合法值校验先行，靶场 25/25）
- 28 存活子域核查 10 个；uis=OpenResty 1.15.8.1（KB 无命中）；www/uis/vpn/pan/szqhjs 零发现
- 会话 BUTIAN-GY-JXNU-20260925-182944；**auth_id=占位值，提交前补真实 cid**
- 教训：verify --rule 整组升级会把最后一次 evidence 套到同组全部条目 → 提交稿逐条核对
- 提交侧待人工补：②归属 ICP ③首页截图 ⑤爱站权重 ⑥活动任务

**22 套 1028 断言全绿**（2026-09-30；同日复核修正：原写 1011 是**漏算** `_test_r001_csp_lab.py` 的 17 条，明细相加本就是 1028）：
36 + 6 + 44 + 67 + 81 + 26 + 8 + 45 + 52 + 40 + 80 + 17 + 18 + 25 + 23 + 57 + 20 + 29 + **45** + 10 + 280 + 19
（api_surface / authgate / authz / closure / coverage / engine_fix / envprobe /
evidence_lint / flow / fp / p1 / **r001_csp** / recon_egress / rules /
**scope_syntax** / service_version / stack / toolchain / **verify_location** / waf_gate /
webui / webui_startup）
—— 2026-09-30 新增 2 套：`_test_scope_syntax_lab`（作用域 DSL + 两实现一致性）、
`_test_verify_location_lab`（复核记录按位置 + CLI 入口自检）；flow 由 46 → 52。

**历史**：15 个靶场 861 条（2026-09-26 平台完善日）：6 + 45 + 81 + 25 + 20 + 44 + 36 +
57 + 80 + 67 + 40 + 46 + 26 + 8 + 280 —— P0×4 根因修复（verify 逐条升级 / :80 环境探针 /
静默失败兜底 / counterevidence 模板）+ receipt / submit --merge-rule / SARIF /
R013 栈指纹扩展（Cookie 名/资源路径/X-*头）+ WebUI 接入 fp_review、credentials、待跟进下钻

- webui 靶场演进：39（接入规则引擎前）→ **122**（UI 第一轮）→ **188**（UI 第二轮）
  → **193**（UI 简化 A）→ **211**（UI 第三轮方案 B+C）→ **218**（方案 D 门禁卡瘦身）
  → **221**（方案 E+F：说明压缩 + 流程节点纯状态）→ **235**（Dashboard 重构：视图切换 + 概览 7 卡）
- 跑法：`PENTEST_NODE=<node.exe> python _test_*.py`；**node 缺失时 webui 的前端 JS
  语法闸会显式 SKIP 且不计入通过**（虚门禁比没门禁更危险），故设了才拿到 188

## DXYSRC（漏洞盒子 / 丁香园安全应急响应中心，2026-09-30）

- 授权编号 `DXYSRC-2026-DXY`；清单 `pentest-orchestrator/auth.dxy.json`（12 条红线逐条抄录）
- 范围：`dxy.cn` / `jobmd.cn` / `biomart.cn` 主域+子域；`=dxy.com`、`=ask.dxy.com`、
  `=mama.dxy.com` **仅该主机**；排除 `!index.dxy.cn`
- 会话 `DXYSRC-2026-DXY-20260930-200821`；108 候选 →（通配基线 + sha256 折叠）→ 12 资产
- **发现 3 条**：R003 ×2（`act.biomart.cn` / `xiaoyuan.jobmd.cn`，低危 3.1，已 confirmed）、
  R009 ×1（`act.biomart.cn` 框架指纹 Laravel，detected，**不进稿**）
- 产物：`out/DXYSRC-2026-DXY-全链路报告.md`（覆盖度 98.1/100 A 级）、
  `out/DXYSRC-提交稿-R003.md`（2 条）
- **提交侧待人工补**：归属证明（ICP/版权/主体全称）、首页截图含地址栏、厂商侧定级
- **缺口**：无登录账号 → R010/R011、越权/IDOR、业务逻辑不可达；`mama.dxy.com` 需微信内置
  浏览器，未覆盖；`ask.dxy.com` H5 未单独跑
- 本轮顺带修掉 4 个平台缺陷：R001 CSP 假阳性 / R001 证据被 `val[:80]` 截断（**尾部被伪造成
  疑似非法 token**）/ R009 缺 counterevidence（违反 D-01）/ WAF 特征库补 2 条（122→124）

## VULBOX-LENOVO（漏洞盒子 / 联想集团 LSRC，2026-09-30 ~ 10-01）

> 与上面「补天联想 SRC」是**同一厂商、不同平台**。授权清单已从补天版改写为漏洞盒子版。

- 授权编号 `VULBOX-LENOVO`；平台 `漏洞盒子 / Vulbox`（`https://lsrc.vulbox.com/`）
- 范围与 2026-09-28 截图**逐条一致**：9 通配域（`lenovo.com` / `lenovo.com.cn` /
  `lenovomm.com` / `lenovo.cn` / `lenovo.net` / `motorola.com` / `motorola.com.cn` /
  `baiying.cn` / `baiying.com.cn`，各含 `*.`）= 18 清单项
- 新增红线：**禁上传 webshell**（一经查实冻结奖金+拉黑）；项目级别 **P0=已申明域 /
  P1=未申明域**（用未申明域名提交 → P1）；评分依据《联想漏洞评分和奖励标准 V6.0》
- 会话 `VULBOX-LENOVO-20260930-230622`；资产 2482 候选（crt.sh 502 + wayback 超时，
  靠 subfinder）→ DNS 筛选 **270 存活**（9 个根域全 NXDOMAIN，无泛解析）→ 精选 **50 台**跑规则引擎
- **发现 5 条，可提交 3 条（全部 confirmed）**：

  | 主机 | 规则 | 分数 | 结论 |
  |---|---|---|---|
  | `mail.baiying.com.cn` | R003 | 6.8 / 6.4 | ✅ 明文 http 200 + **无 Location 不跳转** + 19 个 Set-Cookie 中 15 个会话类缺 Secure |
  | `cn.sso.lenovo.com` | R005 | 5.6 / 5.9 | ✅ Tomcat 8.5.57（8.5.x 分支 2024-03-31 EOL），默认 404 页正文泄露版本，CF 透传 |
  | `account.lenovo.com` | R001 | 3.1 / 2.6 | ✅ `x-content-type-options: nosniffnosniff`（301 与 200 均出现） |
  | `monitor.cochat.lenovo.com` | R009 | 5.3 | ❌ 仅指纹，D-01 不提交 |
  | `shop-pub-gateway.baiying.com.cn` | R003 | 4.2 | ❌ 明文可达但无会话 Cookie，174B 空壳，detected 不进稿 |

- 产物：`out/VULBOX-LENOVO-全链路报告.md` / `-提交稿.md` / `-覆盖度.json` / `-待跟进.json`
  （待跟进 216 条：R008×74、R010×50、R011×50、R013×42）
- 归属证明（实测页面原文，可机器核对）：联想中国官网页脚「版权所有：1998-2026 联想集团」
  + **京ICP备11035381-2**；`www.baiying.com.cn` **同一备案号** → 坐实 `*.baiying.com.cn` 归属
- **本轮修掉 4 个平台缺陷（全部由我自己的前序修复暴露）**：
  1. R014 把 reCAPTCHA **site key** 当凭据报 5.3 —— 但 site key 与 **secret key 同形**
     （都是 40 位 `6L…`，Google 官方口径）→ 整类打 `public` 是**失败方向不安全**
     （真泄的 secret key 会被静默吞掉）。改为 `ambiguous:true` + 按命中上下文判定
  2. R014 上下文覆盖不足：站点用 **JS 配置对象**（`GOOGLE_RECAPTCHA:{PROD_V2:"6L…"}`）
     而非 `grecaptcha(`/`data-sitekey` → 补上下文正则；
  3. R014 被 **base64 内联 SVG** 随机字符流命中（页面 `recaptcha` 出现 0 次）→
     新增「取值必须独立（分隔/粘连判定）」通用过滤，**任何特征正则都可能踩这个坑**；
  4. R001 缺 counterevidence（EL034）。
  附带修：`_build_p1_data.py` 生成器未同步（补丁会被 rebuild 静默冲掉）→ 加往返证明；
  靶场夹具 `_SITEKEY` 实际 49 字符（注释写 40）→ 修为恰好 40。
- 工程失误自纠：曾把 `--interval` 调成 3s 压缩耗时 → 被自己的 `lint` 判 `EL021` 阻断
  （「间隔是合规特性不是性能问题，不得调小」）→ 证据作废，**全量 50 台按 6s 重跑**
- 长跑 runner 首版**单台 `TimeoutExpired` 直接杀掉整轮**（跑 7.5h 挂在第 26 台）→
  改为超时不再致命 + 按 checklog 续跑；`www.motorola.com.cn` 复跑 57.7s 正常 → **偶发挂死**
- 回归：**22 套 1049 通过 / 0 失败 / 0 异常**（p1 87 → 101）

## 待办（优先级降序）

0. ~~平台完善清单~~ → **2026-09-26 晚全部代码项完成**（P0×4 根因 + receipt/merge-rule/SARIF/
   R013 栈指纹/fp_review+credentials 接 WebUI/待跟进下钻），见
   `pentest-orchestrator/平台完善清单_20260926.md` 顶部完成状态。
   剩执行项：jxnu 剩余 9 资产核查、测试账号申请模板
1. 提交回执闭环（**receipt 子命令已落地**，待实战回填平台结论）
2. ikuai8 的 `demo.` / `icc.` 登录态验证
3. ~~**修 `target_in_scope` 两处实现不一致**~~ → **2026-09-30 已修**：抽出
   `scope_match.py` 作为唯一实现（`orchestrator` / `rules_engine` / `webui` 全 import），
   同时新增 `=host`（仅该主机）/`!host`（排除）语法；`_test_scope_syntax_lab.py` 锁
   「两实现结论必须一致」。`coverage.hosts_missing` 的 `host:port` 语义需在下次覆盖度
   变更时复核（当前 rules_engine 侧保留剥端口历史语义）。
4. ~~**复核记录按 rule_id 单条存放导致多位置串稿**~~ → **2026-09-30 已修**：
   `cvss.norm_verify_key` / `find_verification`，存储改「每处发现一份记录」，
   顶层不写 level（fail-closed）；靶场 `_test_verify_location_lab.py`。
5. **Web 端仍未接** `fp_review`（驳回风险预演）与 `credentials`（登录态）——
   规则引擎 / lint / coverage 已于 2026-09-23 接入（②卡片）
6. ~~**平台改动同步线上**~~ → **2026-09-30 晚已完成**：9 个文件（含 `rules/` 三件）
   已同步进 `pentest-webui`，**sha256 逐文件与本地一致**、抽象自检全过、公网 200。
   工具 `deploy/sync_online.py` 本轮改造两点：① bind/image 分类改为**现查
   `docker inspect` 挂载表**（原来硬编码 → 把 `rules/` 当镜像文件 `docker cp` →
   打印假 `[WARN] mounted volume is marked read-only`，结果碰巧正确但假警报
   会训练人忽略 WARN）② 新增 **sha256 全量核对**（「传了但没生效」只表现为
   「行为没变」，不核对发现不了）。详见 HANDBOOK 十六之二。
7. XBEN 外部基准（只读方法学下分数会极低，但这本身把「合规代价」量化出来）
8. ~~**接入本地 Kali**~~ → **2026-09-30 已完成**：平台部署进 VirtualBox Kali VM
   （NAT + 端口转发 `127.0.0.1:2222`），**22 套 1028 断言全绿**（Python 3.14.7），
   与 Windows 基线逐条一致。工具 `deploy/push_to_kali.py`（打 `pentest-orchestrator` +
   同级 `CyberSecurity-Skills-master` 两个顶层目录、四段实证、`--regress`）。
   三条坑见 HANDBOOK 十八：① sshd 僵死实例 →「22 在听但连接被 reset」
   ② 平台依赖仓库外同级目录（漏传 → 4 失败 + 1 套异常，报错只有一句）
   ③ 排除规则必须用通配 `auth.*.json`（逐个列举漏了 6 个授权清单 + 证据截图）。
   **下一步可做**：用 Kali 原生工具链重跑某个已授权项目，对比同批资产的覆盖度/命中有无变化。

