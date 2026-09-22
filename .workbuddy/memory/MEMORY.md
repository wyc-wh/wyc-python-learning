# 项目记忆 - 自动挖洞平台（速查）

> **详细方法论 / 实现细节 / 评估结论在 `HANDBOOK.md`**；过程记录在 `2026-09-21.md`、`2026-09-22.md`。
> 本文只放「不知道就会犯错」的硬规则。

## 骨架

- `pentest-orchestrator/`：`orchestrator.py`(CLI) `rules_engine.py` `rules/`(R001~R014) `scanners.py`(nmap+nuclei) `cvss.py` `exploit.py` `manual_probe.py` `coverage.py` `evidence_lint.py` `credentials.py` `fp_review.py` `_lab_cert.py` `_build_vuln_kb.py`
- `rules/data/`：`service_versions.json` `vuln_components.json` `error_pages.json` `secret_patterns.json` `stacks.json` `fp_rubric.json`
- 方法学文档：`RULES.md`（规则清单与适用边界）、`CLOSURE.md`（闭环纪律）
- 子命令 `init plan autorun engage verify report status check lint submit coverage`
- 合规闸：授权确认 + 范围校验 + `auth.json` + append-only 审计 + 破坏性阶段禁用 + `allow_scanner=false` 硬开关
- 置信度 `detected🔍`→`confirmed✅`→`exploited💥`；**detected 不得提交 SRC**
- `rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS 一律引擎算 `compute_cvss31(8参)`/`compute_cvss40(11参)`；**4.0 只有 N/A/P（UI:R→UI:P）**
- 工具 nmap 7.92 / nuclei v3.11.1 / ffuf / gobuster / feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f；缺 nikto whatweb hydra john
- **本机 shell 三个坑**：① git 用全路径 `~/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe` ② **沙箱 bash 的 PATH 每条命令都被 shim 重置**（`dirname/ls/grep/git: command not found`）→ 命令必须自带 `export PATH=".../usr/bin:.../bin:/c/Windows/System32:$PATH"`，或写全 `.exe` 路径 ③ **PowerShell 的 stdout 抓不到**（只回「Command completed with exit code 0」）→ 别用它取数据

## 补天公益 SRC

- **不需核备案、不需事先报备**（"报备"条款只针对专属 SRC/众测）；**无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只作提交第 2 项「归属证明」
- 红线：禁自动化扫描器 / 高并发 / 破坏性 / 用户数据 / 范围外 / 未授权横向。自律：单线程、间隔 ≥6s、单次 ≤10 请求、全部写审计链
- 提交模板 6 项：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务（②③⑤ 需人工）
- 教训：平台规则先查官方文档，别靠行业通例推断

## 通用工程坑

- **nuclei 必须 `-no-interactsh`**（约 710 模板回连 oast.* 被网关掐断，零输出无提示）
- 去重两层：`(template_id,matched_at)` + `(类别,归一化位置)`；`type=generic` 视为未知类别
- **「工具没装」先怀疑调用侧**：中文 Windows `encoding="utf-8"` 丢输出；端口列表别 `split()`（nmap 会把端口串当主机名）。**耗时=超时整数倍→参数拼错；秒返空→编码问题**
- Windows 不能用 SO_REUSEADDR 探测端口；nmap 无 Npcap 时 `-sV` 挂起→降级 `-sT`；Go 版本号先剥 ANSI 色码
- 合规闸统一 **rc=2 + stderr**（`sys.exit(str)` 是 rc=1）；`_find_exe` 认 `.bat/.cmd/.py`；`python -m <pkg>` 不万能
- `git ls-files` 非 ASCII 转八进制 → `-z`+escape_decode；中文名 ENOSYS → `--ignore-errors`

## 证据铁律（两次翻车换来）

1. **「缺失」与「值为 None」必须字面可区分**：缺失写 `<未声明>` + `*_present` 布尔。**属性不存在的中间表示不能复用「有值」的值域**（曾把缺失读成 `SameSite=None` → 写出「Chrome 会拒绝」这种自我削弱附注）
2. **改了底层函数 ≠ 修好调用点**（`fetch()` 加了 `follow_redirect` 但 `main()` 仍默认跟随）→ 端到端复跑并比对原始输出
3. **urllib 默认跟随 30x**：会把「明文 301」记成「200 不跳转」。判跳转须 `redirect_request` 返 None，再从 `HTTPError.headers` 取 Location
4. **写前自问：这句措辞在帮我还是在帮厂商？** 真实减分项如实写；误读出的必须删
5. **多值头会被 `dict(headers)` 静默截断** → 同发 `XSRF-TOKEN` + `laravel_session` 时**真会话 Cookie 丢失**，证据里只剩 CSRF token。Set-Cookie 必须单独存多值列表 `_all_set_cookies`，解析优先取它
6. **CSRF token ≠ 会话 Cookie**：两者正则必须互斥，否则「会话劫持链」会被一句话驳回
7. **非 200 不能静默丢弃**（既不产 finding 也不产 negative 违反「排除必产 negative」）；≥500 或体积 ≥3× 基线 → 标 `needs_manual_check`（「未取得可判定响应」）
8. **异常响应先取证再下结论**：引擎只记状态码 + 字节数，看不到正文。`rmt` 500/38659B 直觉是 Laravel 调试页，**实为 WAF 拦截页**（`Server: ZS-Proxy21/v201`）；`qmt` 404/11043B 是站点自身 404 页。**按表象写就是幻觉发现。**
9. **前置 WAF 污染状态码判据** → 「未命中」= 「未取得可判定证据」，**不等于**「路径不存在或已防护」，必须写进结论边界

## 措辞铁律（会直接印进报告和提交稿）

- 规则名 / 发现名**不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测 `{bytes}B`。**能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S) + 「安全影响」(C/I/A)，不写套话

## 测试基建铁律

1. 会写真实配置文件的测试**先备份再还原**（曾删掉真实 auth.json）
2. 环境隔离 `PENTEST_AUTH`/`PENTEST_SESSIONS` + `tempfile.mkdtemp()`
3. **靶场红时先分辨「数据脏」还是「代码错」**（P3 首跑 6 红 4 条数据不合格；P4 首跑 6 红 2 条 cookie 名写错）。**别改断言迁就**
4. **靶场必须自检 `status=None`**：忘 `verify_tls=False` 会让 HTTPS 全失败却表现为「站点没内容」→ **假通过**（P2/P4 各踩一次）
5. **规则数量别硬编码**，从 `rules.load_rules()` 动态取
6. **禁止用 `python -c`/bash 内联写含反引号的中文长文本**（反引号被 bash 当命令替换执行，内容静默挖空，踩过**两次**）→ 一律用 Write 写 .py 脚本再执行

## 响应分类与 R014（P1）

- **`base.classify_response()`**（`rules/data/error_pages.json` 120 条）把响应分成报错页 / 拦截页 / 拒绝页 / 目录列举。三条硬边界：①**过泛词**（`error`/`line`/`Internal Server Error`/`server at`）只作旁证，单独采信 = 抑制器自己变假阳性来源 ②**`listing`（Index of / Parent Directory）是正向证据**（CWE-548），禁止用于抑制 ③命中后要**写进措辞**（「实测为 WAF/拦截页（waf:创宇盾）」），不写「疑似」
- **非 200 也必须带分类结论**：`/storage/logs/laravel.log` 返 405/1841B 看着像「未取得 200 内容」，实为**阿里云统一错误页**（`errors.aliyun.com`）→ 含义是「请求在边缘节点就被拦了」，源站有没有这个文件**根本没被判定**
- **跨路径一致性**：多条**不同**路径返回**字节完全相同**的非 200 响应 = 站点通用错误页模板，不是路径内容（qmt：`.git/config` 与 `laravel.log` 都是 404/11043B/同 sha256）。可据此把「需人工查看响应体」降级，但**不解除**「文件是否存在」的疑问
- **R014（凭据/密钥暴露，0 额外请求）**：扫前面规则已取回的响应，排 ORDER 末尾。判据必须「敏感名字 + 赋值号 + 引号值」三要素 + 占位符/低熵过滤（**`\b` 在 `your_api_key` 上不成立**，`_` 属于 `\w`）。**隐私铁律**：只记类别名 + 次数 + 值的长度与字符集，**不记值也不记其哈希**（低熵口令哈希可反查）。与 R008 重叠时以 R008 为准
- **字典库原料「不读就信」是最大风险**：`HTTP/errors.txt` 曾被误判为「WAF 拦截页特征表」，读原文才发现是 **SQL/框架报错串表**。故构建脚本**强制逐条定性**（漏/多/重复一律报错退出）

## 闭环纪律（CLOSURE.md · 移植自 strix）

- **「排除项」不是一个词，是五种状态**：`reported`/`no_issue_found`(测无发现)/`ruled_out`(已澄清)/`not_applicable`(不适用)/`needs_follow_up`(待跟进)。压成一个「排除」= 把「没拿到证据」读成「查过了没问题」
- `negative_result(..., outcome=, evidence=, control=, gap=)`；**`ruled_out` 缺 control 或 evidence 会被自动降级为 `needs_follow_up`**（留 `_degraded_from`）；outcome 拼错抛 `ValueError`。**降级方向永远更保守 —— 宁可说没查清，也不要说安全**
- **`needs_follow_up` ≠ 「已排除」**，报告里单独成表并标注「不得读作安全」。**缺失的证据不是不存在的证据**：无账号 / 预算耗尽 / 判不了 / 跑不起来一律 `needs_follow_up`，**不是** `not_applicable`（R010 以前写「登录态检查不适用」→ 实际是**整个登录态面没覆盖**）
- `ruled_out` 判据：能填完「因为 **<控制点>** 在 **<位置>** 生效，于攻击者可达的每条路径上、在 **<危险效果>** 之前 **<做了什么>**」—— **填不完就不是 ruled_out**
- **只读方法学下唯一合法的升级路径 = 横向事实**：多条**不同**路径返回**字节完全相同**的响应 → 机制可指名 + 证据可核对（sha256）→ 升 `ruled_out`。**边界**：只排除「这个 200 是文件内容」，**不解除**「文件是否存在」的疑问（WAF 同样会）
- **lint 是第二道闸**：EL030(已澄清缺要件·阻断) / EL031(非法状态·阻断) / EL032(待跟进没写缺口) / EL033(未标注状态) / EL034(发现缺反向论证)

## 覆盖度机器观测层（strix 第 2 项）

`coverage.py` ⓪ 段 + `_test_coverage.py` ⑪ 段。**「规则执行了」≠「检查面被覆盖」。**

- **资产维度**分子从「跑过规则的资产」改为 **`_host_effective(h)`**：该资产本轮**取得过有效证据**（有 finding，或至少一条 negative 的 `outcome` ≠ `needs_follow_up`）。全站被前置 WAF 挡死时每条规则都只能产 `needs_follow_up` → 台账写「已核查」，实质连真实响应都没看到。未取得证据者进 `scope.hosts_weak` 单列
- **规则维度改 credit 制**：未执行 0 / **执行了但只产 `needs_follow_up` 0.5** / 取得证据 1.0。半分不是折中拍脑袋：请求发了、响应分析了（成本已付）但**没拿到可判定证据** —— 布尔口径会把「没跑 / 跑了没用 / 有效」压成两种，读数就假了。返回 dict 新增 `rules.{effective,ineffective,credit}`、`scope.{effective,hosts_weak}`
- `render()` 加**计分口径声明**：并排写「台账口径 vs 取得证据口径」，结论边界用 effective 计数。旧 ②b 重复计算段已删
- **⚠️ 现有三份真实产物上读数不变**（`_closure_real_qmt2` / `rules_qmt_jiaoyu_cn` / `rules_bbs_ikuai8_com`：资产 1.0、规则 0.154/0.231/0.077，新旧完全一致）—— 因为它们 `ineffective=[]`（R006/R008/R012/R013 都产了非 `needs_follow_up` 的结论，或压根没跑）。**口径差异只在「有规则只产待跟进」或「有资产被中间层挡死」时才显现**，效果由靶场 ⑪ 段反证覆盖。→ **别把「规则维度低分」当成观测层生效的证据**：低分主因仍是「可达 13 条只跑了 1~4 条」
- **旧产物（CLOSURE 之前写的 `negatives` 无 `outcome` 键）会被 `or "no_issue_found"` 兜成「有效证据」** → 只有新跑的 `check` 才享受新口径。这是**预期**不是 bug

## 外部排除判据库 + 驳回风险预演（strix 第 3 项）

原料 `D:\gihub\strix-main\strix\skills\vulnerabilities\*.md`（29 篇，Apache-2.0），只抽 **False Positives** 段（`Attack Surface`/`Reconnaissance` 要带参探测，与只读方法学冲突，**不抽**）。

- **`rules/data/fp_rubric.json`**（`_build_vuln_kb.py` 生成）：29 类 / **128 条判据**（direct 38 / conditional 25 / out_of_scope 65）+ **10 条规则映射**（R001-R005/R008/R009/R012/R013/R014）+ **5 条跨类纪律 D-01~D-05**。结构 `classes.<key>.fp[]{id,claim,cn,readonly}` + `readonly_default`。**构建脚本强制逐条定性，漏/多/重复即拒绝生成**
- **⭐ D-01（直接纠正本平台）**：**不得仅因信息有助于侦察就给 `C:L`** —— CVSS 的 `C:L` 要求**实际获取了受限信息**。若路径 / 主机名 / 版本 / source map / schema / 调试值**只是暗示**了另一个可能存在的漏洞，要么验证整条链并按验证结果定分，要么保持 `C:N` 且**不提交该报告**。**D-02**：版本→CVE 三步，**第②步必须确认可达性**。D-03 验证码/WAF 拦截表现为登录失败；D-04 未测相关部署就把版本特定行为当普遍行为；D-05 自家基础设施或 catch-all 的软 404
- **`fp_review.py`**（离线 0 请求，**warning 级、不阻断提交**）：`review_finding/review_result/render/render_appendix`；三探针 `_probe_version_banner`(information_disclosure-04) / `_probe_generic_error`(information_disclosure-02) / `_probe_authz_enumeration`(weak_password_detection-04 / idor-05)。接进 `generate_report()`（放在覆盖度之前，含折叠附录）
- **`EL035`**（命中外部排除判据·警告）/ **`EL036`**（向量含 `C:L`/`C:H` 但证据只有 URL+status·警告）：判据收窄到「证据里连一点内容/结构信息都没有」。**实测噪音量 0**（未误报任何已提交稿）
- **R005 据此加「攻击面证据门槛」**：厂商带 `_trigger_condition`（默认不触发）时**版本命中不足** → 从 `ctx.shared` 采攻击面证据（`admin_no_captcha`(R004) / `bypass_cookie`(R002) / `admin_exposed`(R004) / `plaintext_ok`(R003)，**0 额外请求**）；缺证据且在 `MAX_DEFERRED=3` 内 → **不产发现，改产 `needs_follow_up`**（gap 写触发条件 + 补证方式）。无触发条件的组件，版本取证即主要证据
- **编排顺序即检测能力**：`ORDER` 调成 `R006 R001 R002 R003 R004 R013 R005 …` —— **R004 必须早于 R005**，否则 R005 看不到 `admin_no_captcha`，会把高危降级成待跟进
- R012 空容器改用 `outcome="no_issue_found"` + evidence（吸收 idor-05：空数组 / null 是**静默强制**而非暴露，但也不等于「已证明安全」）

## 台账

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效 7.4/7.7）、F-05(6.5)。R012 试跑 8 个 in_scope 资产未命中未授权访问；`demo.`/`icc.` 的 SPA bundle 匿名可下载，匿名请求被 catch-all 兜回首页/404，**需登录态才能验证鉴权**（待办）。`bbs.ikuai8.com` 的 `/.env`、`/.git/config` 均返 **405/1841B**（阿里云边缘节点统一错误页）→ 路径是否存在未判定，**别再重复试探**
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效 6.8/6.4）。11 资产全重跑无高危，**匿名侧确实扎实**；登录态（R010/R011）因无 Cookie 未覆盖 —— 唯一可能翻高危的方向
- **⚠️ jiaoyu 的 SPA bundle 全在认证墙后**（登录页是纯静态「无权限页面」0 个 script，404 也 302 回 login）→「从 bundle 捞 API 清单」对该站无效，**勿重复尝试**。要挖只能靠登录 Cookie（**2 小时过期**，`laravel_session`+`XSRF-TOKEN` 缺一不可，三个子站不通用）
- 回归基线：**11 个靶场 493 条全绿**（6+37+81+25+20+44+36+57+80+67+40）

## 索引

- `HANDBOOK.md` —— 手工只读手法 / 「版本命中官方公告」打法 / 规则引擎 R001-R014 详解 / 证据 lint / 框架指纹 / 覆盖度量化 / 登录态建模 / 闭环纪律 / **覆盖度机器观测层 + 排除判据库（第十二、十三节）** / 图表导出 / 已评估结论（PentAGI、strix、字典库）
- 工程内 `RULES.md` —— 规则清单与每条适用边界
