# 项目记忆 - 自动挖洞平台（速查）

> 详情见 `HANDBOOK.md`：**十一 闭环纪律 · 十二 覆盖度机器观测层 · 十三 外部排除判据库 · 十四 取证与工程纪律全文 · 十五 Web 控制台**。过程记录 `2026-09-21/22/23.md`，目标进展与待办 `LEDGER.md`。本文只放「不知道就会犯错」的要点，一条一句。

## 骨架

- 工程结构 / 子命令 / 合规闸 / CVSS 调用 / 工具清单 → **全文 HANDBOOK 十四**
- 置信度 `detected🔍`→`confirmed✅`→`exploited💥`；**detected 不得提交 SRC**。`rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- **本机 shell 三坑**：① git 写全路径 `~/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe` ② **沙箱 bash 的 PATH 每条命令都被 shim 重置** → 命令自带 `export PATH=".../usr/bin:.../bin:/c/Windows/System32:$PATH"` 或写全 `.exe` ③ **PowerShell 抓不到 stdout**；删文件走 Python `os.remove`

## Web 控制台（webui.py · 详情 HANDBOOK 十五）

- **SystemExit 会静默杀死 Web 请求线程**：合规闸用 `sys.exit(2)`，而 SystemExit 继承 `BaseException`、`socketserver` 只捕 `Exception` → 线程静默结束、客户端收空响应（进程不死，最难查）→ 必须 `_capture()` 兜。**且只回「exit 2」等于没告诉用户原因**，要从捕获日志挑 `[BLOCK]/[FAIL]` 行
- **⚠️ Windows 文件名 ADS 陷阱**：host 带端口时 `rules_x:port.json` 的 `:` 被 NTFS 当 **alternate data stream** → 本体 **0 字节**、内容藏流里，而 `isfile()`/`getsize()` **全部正常**（实测 True/1854B），`ls` 显示 0 字节 → 已抽 `safe_evidence_name()`
- 界面强制自律下限（`interval≥6s`/`max_requests≤10`）并回显 `clamps`；**靶场改小值用 monkeypatch `webui.MIN_INTERVAL`**

## 补天公益 SRC

- **不需核备案、不需事先报备**（"报备"只针对专属 SRC/众测）；**无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只作提交第 2 项「归属证明」
- 红线：禁自动化扫描器 / 高并发 / 破坏性 / 用户数据 / 范围外 / 未授权横向。自律：单线程、间隔 ≥6s、单次 ≤10 请求、全部写审计链
- 提交模板 6 项：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务（②③⑤ 需人工）
- 教训：平台规则先查官方文档，别靠行业通例推断

## 通用工程坑

- **nuclei 必须 `-no-interactsh`**（约 710 模板回连 oast.* 被网关掐断，零输出无提示）；去重两层 `(template_id,matched_at)` + `(类别,归一化位置)`
- **「工具没装」先怀疑调用侧**：中文 Windows `encoding="utf-8"` 丢输出；端口列表别 `split()`。**耗时=超时整数倍→参数拼错；秒返空→编码问题**
- Windows 不能用 SO_REUSEADDR 探测端口；nmap 无 Npcap 时 `-sV` 挂起→降级 `-sT`；Go 版本号先剥 ANSI 色码
- 合规闸统一 **rc=2 + stderr**（`sys.exit(str)` 是 rc=1）；`_find_exe` 认 `.bat/.cmd/.py`

## 证据铁律（两次翻车换来 · 全文 HANDBOOK 十四）

1. **「缺失」与「值为 None」必须字面可区分**：缺失写 `<未声明>` + `*_present` 布尔。**属性不存在的中间表示不能复用「有值」的值域**（曾把缺失读成 `SameSite=None`，写出自我削弱附注）
2. **改了底层函数 ≠ 修好调用点** → 端到端复跑并比对原始输出
3. **urllib 默认跟随 30x**：会把「明文 301」记成「200 不跳转」。判跳转须 `redirect_request` 返 None，再从 `HTTPError.headers` 取 Location
4. **写前自问：这句措辞在帮我还是在帮厂商？** 真实减分项如实写；误读出的必须删
5. **多值头会被 `dict(headers)` 静默截断**，且 **CSRF token ≠ 会话 Cookie**（同发 `XSRF-TOKEN` + `laravel_session` 时真会话 Cookie 会丢）。Set-Cookie 必须单独存 `_all_set_cookies`；两者正则必须互斥，否则「会话劫持链」被一句话驳回
6. **非 200 不能静默丢弃**（违反「排除必产 negative」）；≥500 或体积 ≥3× 基线 → `needs_manual_check`
7. **异常响应先取证再下结论**：引擎只记状态码 + 字节数。**直觉判断两次都被推翻**（疑似 Laravel 调试页实为 WAF 拦截页 / 疑似泄露实为站点自身 404 页）→ **按表象写就是幻觉发现**
8. **前置 WAF 污染状态码判据** → 「未命中」=「未取得可判定证据」，**不等于**「路径不存在或已防护」，必须写进结论边界

## 措辞与测试铁律

- 规则名 / 发现名**不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测 `{bytes}B`。**能被机器验证的写事实，不能验证的别写形容词**；「影响分析」由 CVSS 向量推出利用前提 + 安全影响，不写套话
- 会写真实配置文件的测试**先备份再还原**（曾删掉真实 auth.json）；环境隔离 `PENTEST_AUTH`/`PENTEST_SESSIONS` + `tempfile.mkdtemp()`
- **靶场红时先分辨「数据脏」还是「代码错」**（P3 6 红里 4 条数据不合格；P4 6 红里 2 条 cookie 名写错）。**别改断言迁就**
- **靶场必须自检 `status=None`**：忘 `verify_tls=False` 会让 HTTPS 全失败却表现为「站点没内容」→ **假通过**
- **禁止 `python -c`/bash 内联写含反引号的中文长文本**（被当命令替换执行、内容静默挖空，踩过**两次**）→ 用 Write 写 .py 再执行；**规则数量别硬编码**，从 `rules.load_rules()` 动态取

## 响应分类与 R014（P1 · 全文 HANDBOOK 十四）

- **`base.classify_response()`**（`error_pages.json` 120 条）分报错页 / 拦截页 / 拒绝页 / 目录列举。三条硬边界：①**过泛词**（`error`/`line`/`server at`）只作旁证，单独采信 = 抑制器自己变假阳性来源 ②**`listing`（Index of / Parent Directory）是正向证据**（CWE-548），禁止用于抑制 ③命中后**写进措辞**（「实测为 WAF/拦截页」）
- **非 200 也必须带分类结论**：405/1841B 看着像「未取得 200 内容」，实为**阿里云统一错误页** → 含义是「请求在边缘节点就被拦了」，源站有没有这个文件**根本没被判定**
- **跨路径一致性**：多条**不同**路径返回**字节完全相同**的非 200 响应 = 站点通用错误页模板（qmt：`.git/config` 与 `laravel.log` 都是 404/11043B/同 sha256）。据此可把「需人工查看响应体」降级，但**不解除**「文件是否存在」的疑问
- **R014（凭据/密钥暴露，0 额外请求）**：排 ORDER 末尾。「敏感名字 + 赋值号 + 引号值」三要素 + 占位符/低熵过滤（**`\b` 在 `your_api_key` 上不成立**，`_` 属于 `\w`）。**隐私铁律：只记类别名 + 次数 + 值的长度与字符集，不记值也不记其哈希**（低熵口令哈希可反查）
- **字典库原料「不读就信」是最大风险**：`HTTP/errors.txt` 曾被误判为「WAF 拦截页特征表」，读原文才发现是 **SQL/框架报错串表** → 构建脚本**强制逐条定性**

## 闭环纪律（CLOSURE.md · strix 第 1 项 · 全文 HANDBOOK 十一）

- **「排除项」不是一个词，是五种状态**：`no_issue_found`(测无发现)/`ruled_out`(已澄清)/`not_applicable`(不适用)/`needs_follow_up`(待跟进)/`reported`。压成一个「排除」= 把「没拿到证据」读成「查过了没问题」
- **`ruled_out` 缺 control 或 evidence 自动降级 `needs_follow_up`**（留 `_degraded_from`）；outcome 拼错抛 `ValueError`。**降级方向永远更保守**
- **`needs_follow_up` ≠「已排除」**，单独成表并标注「不得读作安全」。**缺失的证据不是不存在的证据**：无账号 / 预算耗尽 / 判不了一律 `needs_follow_up`，**不是** `not_applicable`（R010 曾写「登录态检查不适用」→ 实际是**整个登录态面没覆盖**）
- `ruled_out` 判据：能填完「因为 **<控制点>** 在 **<位置>** 生效，于攻击者可达的每条路径上、在 **<危险效果>** 之前 **<做了什么>**」
- **只读方法学下唯一合法的升级路径 = 横向事实**：多条**不同**路径返回**字节完全相同**的响应 → 机制可指名 + 证据可核对（sha256）→ 升 `ruled_out`。**边界**：只排除「这个 200 是文件内容」，**不解除**「文件是否存在」的疑问
- **lint 第二道闸**：EL030(已澄清缺要件·阻断) / EL031(非法状态·阻断) / EL032(待跟进没写缺口) / EL033(未标注状态) / EL034(发现缺反向论证)

## 覆盖度机器观测层（strix 第 2 项 · 全文 HANDBOOK 十二）

**「规则执行了」≠「检查面被覆盖」。** 分子从「跑过没有」换成「**取得证据没有**」：**资产**用 `_host_effective(h)`（有 finding，或至少一条 `outcome ≠ needs_follow_up`）；**规则**改 credit 制（未执行 **0** / 只产待跟进 **0.5** / 取得证据 **1.0**）。全站被 WAF 挡死时每条规则都只产待跟进 → 台账写「已核查 8 个资产」实质连真实响应都没看到，这类进 `scope.hosts_weak` 单列

- **⚠️ 三份真实产物上新旧口径读数完全相同**（`ineffective=[]`）→ 差异只在「有规则只产待跟进」或「有资产被挡死」时显现。**别把「规则维度低分」当成观测层生效的证据**（低分主因一直是「可达 13 条只跑了 1~4 条」；旧产物 `negatives` 无 `outcome` 键会被兜成「有效证据」，仅新跑的 `check` 用新口径 —— 预期非 bug）

## 外部排除判据库 + 驳回风险预演（strix 第 3 项 · 全文 HANDBOOK 十三）

原料 strix `skills/vulnerabilities/*.md`（29 篇，Apache-2.0），**只抽 False Positives 段**（Attack Surface / Reconnaissance 要带参探测，与只读冲突）

- **`rules/data/fp_rubric.json`**（`_build_vuln_kb.py`）：29 类 / **128 条判据**（direct 38 / conditional 25 / out_of_scope 65）+ 10 条规则映射 + **5 条跨类纪律 D-01~D-05**。**构建脚本强制逐条定性，漏/多/重复即拒绝生成**；**`out_of_scope` 照收不丢**（它规定「什么样的证据才算数」）
- **⭐ D-01（直接纠正本平台）**：**不得仅因信息有助于侦察就给 `C:L`** —— 要**实际获取了受限信息**；版本 / source map / 路径**只是暗示**了另一个漏洞时，要么验证整条链，要么保持 `C:N` 且**不提交该报告**。**D-02**：版本→CVE 三步，**第②步必须确认可达性**
- **`fp_review.py`**（离线 0 请求、**warning 级不阻断提交**，接进 `generate_report()`）+ **`EL035`/`EL036`**，判据收窄到「证据里连一点内容/结构信息都没有」否则变噪音源 —— **实测噪音量 0**
- **R005 攻击面证据门槛**：厂商带 `_trigger_condition`（默认不触发）时**版本命中不足** → 从 `ctx.shared` 采上游事实（**0 额外请求**）；缺证据且在 `MAX_DEFERRED=3` 内 → **不产发现、改产待跟进**。**`ORDER` 里 R004 必须早于 R005**，否则看不到 `admin_no_captcha` 会把高危降级

## 台账

→ **已拆到 `LEDGER.md`**（目标进展 / 待办 / 回归基线），本文不重复。
速记：ikuai8 = F-10 高危（7.4/7.7）；jiaoyu = J-01 中危，匿名侧扎实、登录态未覆盖；回归基线 **12 靶场 532 条全绿**。
