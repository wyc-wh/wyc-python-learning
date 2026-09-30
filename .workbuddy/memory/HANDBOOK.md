# 雷神之锤自动挖洞平台 - 方法学手册（MEMORY.md 的详情层）

> 本文件不承载「每次都要记住」的铁律，只在需要时查阅。铁律见 `MEMORY.md`。

## 一、手工只读核查手法（命中率降序）

`manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`（仅 GET / ≥6s / ≤6 请求）

1. **⭐版本 → 厂商官方公告的受影响区间**（见 §二）
2. 抓首页 href 的 host 找业务系统（比 crt.sh 有效）
3. 客户端安全控制绕过：读 JS，若只是 `document.cookie=`+reload、服务端不校验 → 一条 curl 头绕过（CWE-602）
4. 后台入口常不在前台防护范围内（`admin.php` 单独查）；弱口令可行性先搜 `seccode/验证码/captcha`，有就别碰
5. 软 404 用 sha256 比对（200 但与首页同 hash = catch-all）
6. 明文 HTTP 分资产测（有 HSTS ≠ 80 端口跳 HTTPS）
7. 归属证明取首页页脚；SPA 站去 `app.<hash>.js` 搜「版权所有/京ICP/有限公司」
8. 版本排除法：先查修复版本，别硬套 CVE
9. 零破坏写鉴权探测：`DELETE /api/xxx/999999999`（不存在的 ID）→ 返「未登录」=安全，返「成功」/404=鉴权缺失
- **「无测试账号」= 教育/政务类 SRC 硬阻塞**，必须提前说明预期。严禁注册真实手机号、严禁测短信频控

## 二、⭐「版本命中官方公告」打法

**困境**：SRC 不许爆破，「无限爆破风险」怎么证明？
**解法**：拆成两条**可只读取证**的事实 —— ①版本落在厂商官方公告的受影响区间 ②站点未部署官方认可的缓解措施。两条成立即 confirmed，**不需要真爆破**。

- **⚠️ 版本命中 ≠ 漏洞成立**：必须再查公告的**触发条件**。Discuz!【2021】第1号明写「安装时默认不触发，需管理员在 UCenter 保存设置使 `login_failedtime=0` 才触发」→ 只报版本命中会被『默认不触发』一句驳回。补证：用**不存在的用户名**发一次登录失败，提示恒为「还可尝试 4 次」即触发（单次，非爆破）
- 公告的「修复版本」要核对属于**哪一份公告**（曾把 10 月公告的 X3.4 Release 20211124 错当 6 月公告的修复版本，后者是「2021-06-29 及以后」）
- 国内 CMS 以**厂商官方公告**为准（CVE 次之）；版本清单逐条比对确认**被点名**；记下修复版本与 EOL。公开研究只能作「风险升级说明」并**标注未验证**
- 实例 F-10 定级：CWE-307 + CWE-1104，`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`（=7.4）

## 三、只读规则引擎（核心能力）

`rules/` + `rules_engine.py` + `check` 子命令。**不是扫描器**：无 payload / 不遍历 / 不并发 / 只 GET·HEAD → **不受 `allow_scanner` 闸约束**，但强制范围校验 + 限速 ≥6s + 请求预算 + 审计链。置信度恒为 **detected**；**排除必产 negative**；预算耗尽标 `unfinished`。

规则清单：R001 安全头占位符 / R002 客户端绕过 / R003 明文+Cookie / R004 后台入口 / R005 版本命中公告 / R006 catch-all 基线(抑制器) / R007 零破坏写探测(默认关) / R008 敏感文件 / R009 框架指纹 / R010 凭据有效性 / R011 双态鉴权差异 / R012 无账号打访问控制 / R013 版本提取(R005 的原料) / R014 凭据暴露扫描(0 额外请求)

- `ORDER`：R006 先跑（基线）；R002 先于 R005（绕过后的页面才有版本信息）；**R013 先于 R005** —— **编排顺序本身就是检测能力的一部分**
- **关联分析比单条重要**：COR-T01(R001∧R003)=6.8；COR-A01(R004∧R005)=7.4。用 `supersedes` 避免重复提交
- **R012（无账号打访问控制）**：从站点自身公开的 JS bundle 提路径（不遍历不猜），匿名 GET 返 200 + JSON + 有业务字段 → 未授权访问。敏感路径 7.5 / 其余 5.3。硬前提：**bundle 必须匿名可达**（前端在认证墙后的站结构性失效）
- **R013（R005 的原料供给者）**：104 条版本正则从**响应头 + 正文**提「产品+版本」→ 写 `ctx.shared["service_versions"]` → 供 R005 比对公告。**自身只产排除项不产 finding**（版本暴露按 CVSS 3.1 算确实是 5.3，但公益 SRC 不单独收，且每站一条会淹掉报告）。两个知识源互补：`service_versions.json`（服务端/中间件，源自 Burp 规则集）+ `vuln_components.json#version_regex`（国产 CMS）
- **关键区分**：「未提取到版本」可能是 ①没暴露 ②需登录 ③**被 WAF/CDN 改写了 Server 头**。实测 qmt=`ZS-Proxy21/v201`、ikuai8=`Tengine`+`Ali-Swift/EagleId`。措辞必须区分三者，否则覆盖度结论是假的
- **证据只存结构不存值（隐私铁律）**：API 响应可能含个人信息。只记字段名 / 条数 / sha256 / content_type，**绝不记录返回值**（确认时自行 curl 看，别把数据贴进报告）

### 实现要点（复用时避开）

- **缓存 key 必须含请求头**：只按 (method,url) 会吞掉 R002 的第二次请求（漏报且不报错）。也因此登录态 / 匿名态天然隔离
- `OpenerDirector.open()` 不接受 `context=`：关 TLS 校验要 `build_opener(HTTPSHandler(context=ctx))`
- `Powered by <a>X 3.3</a>` 正则里 `<...>` 必须整体可选 `(?:<[^>]*)?`
- 根路径跳 HTTPS ≠ 后台也跳：R003 需对后台入口二段复检
- 靶场用**协议嗅探在单端口同时服务 HTTP/HTTPS**（首字节 0x16 = TLS ClientHello）
- **靶场 openssl 依赖 PATH，环境一变就崩在起步阶段**（证书生成在 serve_forever 之前 → 终端只显示空输出，极易误判成「规则改坏了」）。已抽 `_lab_cert.py` 自动定位 PortableGit 自带 openssl.exe，四靶场共用一个入口，**改一处即可**

## 四、证据自检 lint

`evidence_lint.py` + `orchestrator lint`。靶场 37/37。17 条断言（EL001-EL029），离线不发请求。
**存在理由**：两次翻车的共同结构是**取证层取值正确、表述层结论错误**，单测抓不到。
最巧三条：**EL004** 证据 sha256 与请求流水里另一 URL 相同 → 跟随跳转；**EL009** 自我削弱措辞（引述语境豁免）；**EL002** `*_present=False` 却写成「属性=某值」。
接入五处（缺一处门禁就是虚的）：`run_check` 出口 / `check --strict` / `lint --file|--session` / `report` 小节 / **`submit` 门禁**（阻断项默认不出稿，`--force` 才出且留痕）。
**结论文本与修复建议必须分开检查**：`remediation` 里「应设为 SameSite=None」是建议值，计入会误报。

## 五、框架指纹

`rules/data/stacks.json`（14 栈）+ R009。靶场 20/20。
**要解决的问题**：R001~R008 全是通用配置检查，命中率有天花板 —— 缺「这站是什么栈、该栈高发什么」。
三条硬边界：①指纹识别 **0 额外请求**（复用 R006 基线 + R002 绕过缓存）②定向探针**默认不跑**（仅 `--deep`，每栈 ≤4，全 GET）③**`_never_probe` 永不自动请求**（ThinkPHP invokefunction / SpringBoot actuator heapdump / Jenkins script）
**刻意不写 CVE 编号**：只给官方公告入口 + 风险类型，命中后 `needs_manual_check=True`。**臆造 CVE 明令禁止。**
可靠度 high/medium/low，**low 不单独采信**；**同栈多命中取可靠度最高，不是第一条**（曾把 qmt 的 XSRF-TOKEN(medium) 当首选而漏 `laravel_session`(high)）。
实战：bbs.ikuai8 → Discuz!(body,high)；qmt.jiaoyu → Laravel(cookie,medium)。**Discuz 只在带 R002 绕过时才命中。**
**⭐ body 指纹正则必须加词边界**（2026-09-25 dihuangbox 翻车）：weaver 的 `E-Mobile`
被正常 meta `apple-mobile-web-app-status-bar-style` 的子串 `e-mobile` 命中，
任何带该 meta 的站都会被误报成泛微 OA。修复：`\bE-Mobile\b|\bweaver\b`。
**新增指纹前先在真实站点上做子串自检**：把模式逐个 `in` 到一页普通 HTML 里看会不会误中。

**⭐ R001 判定顺序：合法值校验必须先于占位符黑名单**（2026-09-25 vpn.jxnu 翻车）：
通用占位符黑名单含 `^none$`（本意抓 `X-Frame-Options: none`），但
`X-Permitted-Cross-Domain-Policies: none` 是合法枚举值 → 先跑黑名单会误杀。
修复：先过 `HEADER_SPECS` 该头自己的 valid_re，合法即跳过。
**新增安全头时必须同步核对：它的合法值集合是否与占位符黑名单相交。**

**⭐ verify --rule 是整组升级**：同一 rule_id 的全部发现项共享最后一次的
evidence/note —— 多目标同规则（如 3 个站都命中 R003）时，提交稿里每条的
【人工复核】会串成最后一条的内容。**出稿后逐条核对复核文字**，串了就按位置改写。

## 六、覆盖度量化

`coverage.py` + `orchestrator coverage`。靶场 81/81（含 ⑪ 段机器观测层 19 条）。
**必须拆两个数**：`score` 核查完成度（相对当前方法学可达范围，多跑就涨）/ `ceiling` 方法学上限（匿名 + 只读 + conservative = **20%**，结构性）。
**刻意不把 ceiling 计入 score**：否则匿名只读永远不及格 → 分数失去区分度。结构性限制单列：不掩盖，也不污染可改进项。
五维度权重：资产 0.30 / 规则 0.25 / 完整性 0.15 / 栈定向 0.15 / 证据质量 0.15。`绝对覆盖度 = score × ceiling / 100`。
分母：资产取 `in_scope`（`out_of_scope` 不混入）；规则 = 全量 − 需写探测且未开启的；无证据时证据维度 = 0；有 `unfinished` → 完整性 50% + blocker gap。
**副产品：改进收益排序** `gain=(1-score)×weight×100` 降序。直觉以为「1/3 资产」比「1/8 规则」缺口大，实际规则 21.9 > 资产 20.0 —— **边际收益必须算，不能猜**。

**⓪ 机器观测层（第 2 项，详见第十二节）**：资产 / 规则两个维度的分子都从「跑过没有」
改成「**取得证据没有**」—— 资产用 `_host_effective()`，规则用 credit 制（0 / 0.5 / 1.0）。
`render()` 里并排写出两种口径。**这是把「规则执行 ≠ 检查面被覆盖」从口号变成分数的那一步。**

## 七、登录态建模

`credentials.py` + R010/R011 + stacks.json 的 `auth_paths`。靶场 44 条。
**存在理由**：匿名态下 auth 因子 0.5，所有需登录的功能点 / 越权 / 业务逻辑不可见。有测试账号则 ceiling 翻倍（20%→40%）。
**凭据值零落盘（最硬边界）**：证据 / 审计 / 会话 / 报告里**只有 fingerprint 与 cookie 名**，`Identity.as_dict()` 是唯一落盘出口。请求流水记 `anon|<指纹>`。凭据文件进 .gitignore。**不提供「用账号密码自动登录」**（必触验证码 / 短信，且易滑向口令爆破）。
**R010 必须先于 R011**：凭据无效时 R011 双态一致会得出**假的阴性**（漏报）而非「没法判断」。两种判据：①响应差异 ②**Set-Cookie 差异**（不可省 —— 很多站首页两态同内容，只靠 ① 会全判 inconclusive，而它们恰恰可能藏着最严重的鉴权缺失）。
**R011 三重假阳性抑制**：catch-all 兜底 / 登录错误页 / **首页 `/` 排除**。凭据 invalid/inconclusive 时**拒绝下结论**。
三个真 bug：①登录页正则别写 `Log\s*in`（未登录站首页必有 `/login` 链接 → 几乎所有站被误判「踢回登录页」）②**请求失败 ≠ 两态不同**（sha256 空，`a==b` 失效 → 假成功）③别用 `bytes<200` 判空壳（滤掉 103B 真页），用 `base.looks_like_content()`

## 八、链路

`check → verify --rule → report → submit`
- `session["rule_checks"][host]` = check 结果（**合并语义**：本轮 rule_id 覆盖旧的，未跑到的保留）；`session["rule_verifications"][rule_id]` = 人工复核升级
- `check --import-file` 零请求导入；report / verify / submit 均支持 `--session`

## 九、图表导出

`show_widget` 用 CSS 变量，脱离宿主不显示。出附件时单独写 SVG **写死颜色**（浅色 #F1EFE8 底 / #D3D1C7 边 / #2C2C2A 字，危险 #FCEBEB / #A32D2D），转 PNG 用 Edge headless；校验尺寸 `struct.unpack('>II', d[16:24])`

## 十、已评估、勿重复评估

- **PentAGI**（`D:\gihub\pentagi-main`，MIT，Go+Docker 12 服务）：**只借鉴方法论，不集成架构** —— Go/Python 不兼容、过度工程、其「Never request permission」与人工确认制对撞、全攻击链自动化对 SRC 是合规风险。已借鉴：置信度三级 / 覆盖度 / 脱敏 / CLI 反幻觉协议。
- **Strix**（`D:\gihub\strix-main`，Apache-2.0，Python 226 文件 / 源码 40.6k 行 + 技能库 690KB）：**不集成代码，但方法论借鉴价值高于 PentAGI 与字典库** —— 它是自主 AI 渗透 agent（Docker 沙箱 + Caido 代理 + Playwright + shell + Python exploit runtime + 多 agent 编排），执行模型要发 payload/起 shell，与补天公益禁自动化扫描器与破坏性操作**直接冲突**；依赖 Docker + LLM + `openai-agents` SDK，与「零依赖纯标准库」不兼容；**全仓无授权闸**（只有 README 一句 WARNING，`core/inputs.py` 的 authorized_targets 只是给 agent 的范围上下文，非强制校验）。XBEN 104 题 96% 成功率（v0.4.0）。
  借鉴（按价值）：① `strix/skills/analysis/counterevidence.md` —— 闭环纪律，**已落地，见第十一节**；② `report/coverage.py` + `tools/coverage/tools.py` —— **自我陈述 vs 机器观测双源 + 矛盾即 gap**，**已落地，见第十二节**；③ 29 类漏洞知识库（`skills/vulnerabilities/*.md`，292KB）结构固定为 Attack Surface / Reconnaissance(参数清单) / Validation / **False Positives** / Impact → 抽取式可用，**已落地第 3 项（只抽 False Positives），见第十三节**；④ `severity_change_conditions` 字段；⑤ `report/sarif.py` SARIF 2.1.0；⑥ 外部基准 XBEN。⚠️ **`False Positives` 那节对本平台直接致命**：`information_disclosure.md` 明写「Version banners with no exposed vulnerable surface and no chain」不算 —— **正对着 R013/R005 的打法**，**已消化为 D-01 + R005 攻击面证据门槛**（第十三节）。
- **字典库**（`D:\gihub\Dictionary-Of-Pentesting-master`，913MB / 4991 文件）：**只能「抽取式集成」**。关键判断：**99.96% 是给扫描器 / 爆破器用的**（口令、用户名字典、御剑/DirBuster 目录爆破、xxe/top25 参数 fuzz、2M 子域字典、UA 池）→ 全部踩补天红线，禁用。真正能用的约 400KB，边际价值排序：**版本正则 > 错误页特征 > 密钥正则 > 路径库**（nuclei 13742 模板已有类似路径内容，边际低）。

| 可集成 | 对接 | 补什么缺口 |
|---|---|---|
| `CMS/Burp_Software-version-checks/match-rules.tab` 113 条 regex→产品+版本 | R009/R005 | 版本自动提取（R005 一直靠 meta generator 人工取，是瓶颈） |
| 敏感路径分类库（actuator 35 / swagger 54 / graphql 12 / k8s 57 / juicy 50 / leaky-misconfigs 461） | R008 | 现在 CANDIDATES 只有 5 条硬编码。**必须按栈定向取 ≤8 条，禁全库遍历** |
| `HTTP/errors.txt` 97 条错误串 | 假阳性抑制 | 治第三次翻车（WAF 拦截页 / 站点 404 页骗过判据） |
| `Regex/api_key.txt` + `HTTP/secret-keywords.txt` 104 条 | R008 内容匹配 | 密钥 / AK / SK / JWT 泄露识别。**只存命中类型，禁存值** |
| `Subdomain/cdn_waf_server.txt` 347 条后缀（低优先） | 新能力 | 判断目标是否前置 WAF → 状态码判据被污染时自动降级结论 |

**执行进度**：**P0 已完成** —— 版本正则落地为 R013（`service_versions.json` 104 条 + `rules/R013_service_version_extract.py`），并顺带做了第 5 项的前半（前置 WAF/CDN 识别，写进 R013 排除项措辞）。
**P1 已完成** —— ①错误页/异常响应分类落地为 `rules/data/error_pages.json`（120 条）+ `base.classify_response()`，接进 `looks_like_content()` 与 R008/R012 措辞；顺带把「中间层统一错误页」与「跨路径一致性」两条实战判据固化 ②密钥正则落地为 `rules/data/secret_patterns.json`（22 条 provider + 1 条赋值式）+ `rules/R014_credential_exposure.py`（**0 额外请求**，扫已取回的响应）。靶场 `_test_p1_lab.py` 78 条。
**P1 未做（边界）**：敏感路径分类库（actuator/swagger/graphql/k8s/juicy/leaky 共 669 条）对 R008 —— **必须按栈定向取 ≤8 条，禁全库遍历**；`Subdomain/cdn_waf_server.txt` 347 条后缀（低优先）。

**⚠️ 定性纠偏（重要）**：`HTTP/errors.txt` 那 97 行**不是「WAF 拦截页特征表」**，
而是 **SQL/ODBC/JDBC/ORA/PHP 报错串表**。原先的评估只看文件名就写了用途 ——
教训：**「可集成」的判断必须等读完原料再下**。重定性后它有三个互不相同的用途：
①抑制（报错页不算内容）②正向证据（`Index of` / `Parent Directory` = CWE-548）
③反例（`error` / `line` / `server at` 过泛，单独采信等于永远命中）。
`secret-keywords.txt` 69 行与 `access_key` / `secret_key` 两条是**裸关键词/裸名字**，
一律不许单独成规则，只并入「赋值式」检测的名字集合。

## 十一、闭环纪律（CLOSURE.md · 移植自 strix counterevidence）

**为什么做**：发现项有三级置信度兜着，**排除项只有一个「排除」**。于是三种完全
不同的情况被写成同一句话 —— 确实没有 / 有机制解释 / **没拿到证据**。
第三种读起来像「已证明安全」，实际是漏报的典型成因。

**三种病例**：① jiaoyu 无测试账号 → 旧措辞「登录态检查**不适用**」，实际是
整个登录态面没覆盖、ceiling 从 40 腰斩到 20；② jiaoyu 的 R013 版本提取全失败
（WAF 改写 Server 头）被记成「排除」→ **R005 实质未生效在台账上完全看不见**；
③ Discuz!「默认不触发」—— 外部判据给出立场：**运维可配置性不构成控制**
（但站点侧仍须取证）。

**五级状态**：`reported` / `no_issue_found`(测无发现) / `ruled_out`(已澄清) /
`not_applicable`(不适用) / `needs_follow_up`(待跟进)。
`ruled_out` 的判据是能填完这句话：
「因为 **<控制点>** 在 **<位置>** 生效，于攻击者可达的每条路径上、
在 **<危险效果>** 之前 **<做了什么>**」—— **填不完就不是 ruled_out**。

**实现四处 + 两道闸**：
- 构造函数 `rules/base.py::negative_result`（五级校验 / 自动降级 / 非法值抛错 /
  `needs_manual_check=True` 强制 needs_follow_up）
- 规则 R006 / R008 / R010 / R011 / R013 显式标注
- lint `EL030`–`EL034`（第二道闸，抓「用 dict 绕过构造函数」的历史写法）
- `coverage.closure.{tally,ineffective_rules}` + 报告分表渲染
  （`orchestrator._rule_checks_section`：已澄清表 vs 待跟进表，已澄清附控制点）
- 靶场 `_test_closure_lab.py` 67 条：五种站点形态 × 五级状态

**只读方法学下唯一合法的升级路径**：横向事实 —— 多条不同路径返回字节完全相同的
响应 → 机制可指名 + 证据可核对 → 升 `ruled_out`。`R008` 的 `_upgraded_from` 痕迹。
边界：只排除「这个 200 是文件内容」，**不解除**「文件是否存在」的疑问。

**顺带修的一处**：`/.env` → **302**（qmt 实测重定向到 `/login?data=...`）以前记
「测无发现」，但重定向说明「服务端把该路径路由到了别处」，存在性同样未判定
→ 措辞必须带上重定向目标与该边界。

**未做（边界）**：① `counterevidence` / `severity_change_conditions` 未结构化
（只有 EL034 提示）；② `not_applicable` 无真实用例（**不为用满枚举值而硬塞**）。
（原「第 2 / 3 项」已完成，见第十二、十三节。）

## 十二、覆盖度机器观测层（strix 第 2 项）

**为什么做**：第十一节的 `closure.ineffective_rules` 只是把「跑过、只产待跟进」的规则
**列进 gaps**，分数照旧按「跑没跑」算 —— 于是 jiaoyu 那份 100/100 在账面上依然漂亮，
尽管它的 R013 实质没生效、R010/R011 整个登录态面没覆盖。**矛盾说出来了，却没进分数。**

**改法**（`coverage.py`）：分子从「跑过没有」换成「**取得证据没有**」。

| | 旧（台账口径） | 新（取得证据口径） |
|---|---|---|
| 资产维度 | 有 `rule_checks` 记录即算 | `_host_effective(h)`：有 finding，或**至少一条** negative 的 `outcome ≠ needs_follow_up` |
| 规则维度 | 布尔：跑过 = 1 | credit：未执行 **0** / 只产 `needs_follow_up` **0.5** / 取得证据 **1.0** |

- `_host_effective` 要解决的场景：**整站被前置 WAF 挡死**时，每条规则都只能产
  `needs_follow_up` —— 台账上写着「已核查 8 个资产」，实质连它的真实响应都没看到。
  这类资产进 `scope.hosts_weak` 并被单列成 major gap，**不计入有效核查**
- **0.5 不是折中拍脑袋**：请求确实发了、响应确实分析了（这部分成本已付），但
  **没有拿到任何可判定证据**。布尔口径会把「完全没跑 / 跑了没用 / 有效」三种压成两种
- 返回 dict 新增 `scope.{effective,hosts_weak}` / `rules.{effective,ineffective,credit}`；
  `render()` 加**计分口径声明**并排写出两种口径，结论边界一律用 effective 计数

**⚠️ 一个必须记住的实测反直觉结论**：**现有三份真实产物上新旧口径读数完全相同。**

| 产物 | 资产 | 规则 | 无效规则 |
|---|---|---|---|
| `_closure_real_qmt2.json`（qmt，实跑 R006/R008） | 1.0 → 1.0 | 0.154 → 0.154 | — |
| `rules_qmt_jiaoyu_cn.json`（qmt，实跑 R006/R013/R005） | 1.0 → 1.0 | 0.231 → 0.231 | — |
| `rules_bbs_ikuai8_com.json`（bbs，实跑 R012） | 1.0 → 1.0 | 0.077 → 0.077 | — |

原因：这些产物 `ineffective = []` —— 跑过的规则都产了非 `needs_follow_up` 的结论，
没有资产被中间层挡死。**口径差异只在「有规则只产待跟进」或「有资产被挡死」时才显现**，
所以它的效果由靶场 `_test_coverage.py` ⑪ 段（含两条反证 + 跨资产汇总）覆盖，而不是靠真实产物。

两个直接推论：
1. **别把「规则维度低分」当成观测层生效的证据** —— 低分主因一直是
   「可达 13 条只跑了 1~4 条」，不是观测层扣的
2. **旧产物（CLOSURE 之前写入的 `negatives` 没有 `outcome` 键）会被
   `or "no_issue_found"` 兜成「有效证据」** → 只有新跑的 `check` 才享受新口径。
   这是**预期**，不是 bug

**⑪ 段的三条反证**（`_test_coverage.py`）：① 规则只产待跟进 → 得半分 → 总分确实下降
② 整站只产待跟进 → 该资产不计入有效核查 ③ 跨资产汇总 —— 他处取得过证据则不算 ineffective。

## 十三、外部排除判据库 + 驳回风险预演（strix 第 3 项）

**原料**：`D:\gihub\strix-main\strix\skills\vulnerabilities\*.md`（29 篇，Apache-2.0）。
只抽 **False Positives** 段（128 条排除判据）；`Attack Surface` / `Reconnaissance`
需带参探测，**与只读方法学直接冲突，不抽**。29/29 篇都含 Validation + False Positives。

**产物 ①：`rules/data/fp_rubric.json`**（生成脚本 `_build_vuln_kb.py`）

- 29 类 / **128 条判据**（direct **38** / conditional **25** / out_of_scope **65**）
  + **10 条规则映射**（R001 R002 R003 R004 R005 R008 R009 R012 R013 R014）
  + **5 条跨类纪律 D-01~D-05**
- 结构：`classes.<key>.{cn, readonly_default, count, fp[]{id,claim,cn,readonly}}`
- **三档怎么定**：`direct` = 只靠已取回的 GET/HEAD 响应即可判定；
  `conditional` = 需特定条件（带参 GET / 测试账号 / 一次已授权探测）但判据在只读框架内成立；
  `out_of_scope` = 需写操作 / payload 利用 / 服务端行为观测，只读下不可判 ——
  **仍收录**，因为它规定了「什么样的证据才算数」
- **抽取式集成纪律**：`_build_vuln_kb.py` 把 29 类名与 128 条中文释义写成有序常量，
  **强制逐条定性，条数不符 / 漏 / 多 / 重复即拒绝生成**（同 P1 字典库的教训）

**⭐ D-01 直接纠正本平台**：**不得仅因信息有助于侦察就给 `C:L`。** CVSS 的 `C:L`
要求**实际获取了受限信息**。若路径 / 主机名 / 版本 / source map / schema / 调试值
**只是暗示**了另一个可能存在的漏洞，要么**验证整条链并按验证结果定分**，
要么**保持 `C:N` 并且不提交该报告**。
→ 这正是 `information_disclosure.md` 那句「Version banners with no exposed vulnerable
surface and no chain」的机器化。**D-02**：版本→CVE 三步，**第②步必须确认可达性**。

**产物 ②：`fp_review.py`**（离线、0 请求、**warning 级不阻断提交**）

- `review_finding(f)` / `review_result(cr)` / `render(rep)` / `render_appendix(rep)`
- 三个探针：`_probe_version_banner`(information_disclosure-04) /
  `_probe_generic_error`(information_disclosure-02) /
  `_probe_authz_enumeration`(weak_password_detection-04 / idor-05)
- 接进 `generate_report()`，位置在**覆盖度之前**，附录用 `<details>` 折叠

**产物 ③：`EL035` / `EL036`**（新增两道警告级门禁）

- `EL035` 命中外部排除判据（来自 `fp_rubric.json` 的 rule_map）
- `EL036` 向量含 `C:L` / `C:H` 但证据里**只有 URL + status** —— 判据刻意收窄到
  「证据里连一点内容 / 结构信息都没有」才报，避免自我削弱式误报
- **实测噪音量 0**：在全部已提交稿上未触发一次

**产物 ④：R005 加「攻击面证据门槛」**（`rules/R005_eol_component.py`）

- 厂商公告带 `_trigger_condition`（如 Discuz!「默认不触发，需管理员保存 UCenter 设置」）
  → **版本命中不足以支撑发现**，必须再取攻击面证据
- `_attack_surface(ctx)` 从 `ctx.shared` 复用上游事实，**0 额外请求**：
  `admin_no_captcha`(R004) / `bypass_cookie`(R002) / `admin_exposed`(R004) / `plaintext_ok`(R003)
- 缺攻击面证据且在 `MAX_DEFERRED = 3` 内 → **不产发现，改产 `needs_follow_up`**，
  gap 里写清触发条件与补证方式。无 `_trigger_condition` 的组件，版本取证即主要证据
- 发现项 evidence 新增 `attack_surface`；note 改为落实测事实
- **编排顺序即检测能力**：`ORDER` 调成 `R006 R001 R002 R003 R004 R013 R005 …` ——
  **R004 必须早于 R005**，否则 R005 看不到 `admin_no_captcha`，会把高危降级成待跟进
- 靶场改造：`_test_service_version_lab.py` 新增 `P_DISCUZ_FULL` / `site_discuz_full`；
  ① 改为**反证**（缺攻击面证据 → 不产发现、改产待跟进），①b 补攻击面证据 → R005 才产出 7.4

**产物 ⑤：R012 吸收 idor-05** —— 空数组 / null 改用 `outcome="no_issue_found"` + evidence：
**空容器是「静默强制」而非暴露，但也不等于「已证明安全」**。

**靶场**：`_test_fp_lab.py` 40 条（知识库完整性 + fp_review 命中/不误报 +
EL035/EL036 门禁反证 + 渲染 + 离线保证）。
**全量回归 11 个靶场 493 条全绿**。

## 十四、取证与工程纪律（详情层 · MEMORY.md 的展开）

> MEMORY.md 里这些条目只有一句要点，全文在此。

### 骨架清单

`pentest-orchestrator/`：`orchestrator.py`(CLI) `rules_engine.py` `rules/`(R001~R014)
`scanners.py`(nmap+nuclei) `cvss.py` `exploit.py` `manual_probe.py` `coverage.py`
`evidence_lint.py` `credentials.py` `fp_review.py` `_lab_cert.py` `_build_vuln_kb.py`。
数据：`rules/data/` 下 `service_versions.json` / `vuln_components.json` / `error_pages.json` /
`secret_patterns.json` / `stacks.json` / `fp_rubric.json`。
文档：`RULES.md`（规则清单与适用边界）、`CLOSURE.md`（闭环纪律）。
子命令：`init plan autorun engage verify report status check lint submit coverage`。
合规闸：授权确认 + 范围校验 + `auth.json` + append-only 审计 + 破坏性阶段禁用 +
`allow_scanner=false` 硬开关。工具：nmap 7.92 / nuclei v3.11.1 / ffuf / gobuster /
feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f（缺 nikto whatweb hydra john）。

**本机 shell 三个坑**：① git 用全路径
`~/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`
② **沙箱 bash 的 PATH 每条命令都被 shim 重置**（`dirname`/`ls`/`grep`/`git` 全 command not found），
`export PATH=...` 在 `&&` 链里也可能被重置 → 每条命令自带 export，或直接写全 `.exe` 路径
③ **PowerShell 的 stdout 抓不到**（只回「Command completed with exit code 0」）→ 别用它取数据。
POSIX `rm` 被 shim 包了一层 safe-delete，同样受 ② 影响 → 删文件可用 Python `os.remove`。

**`.gitignore` 约定（哪些产物不入库）**：凡「真实目标取证产物」一律忽略，判据是
**文件里出现真实主机名 / 路径 / 响应元数据** —— 与 `.sessions/` 同类，属本地产物。
已忽略：`pentest-orchestrator/rules_*.json`（规则检查单资产快照）、
`pentest-orchestrator/_*.log`（真实目标运行日志）、`pentest-orchestrator/_appendix_*.md`
（按目标生成的报告附录 / 提交稿素材）、`cred*`（P4 凭据）。**别为了「留痕」把它们提交**：
需要留痕的是**方法与结论**（HANDBOOK / LEDGER + 报告正文），不是原始响应元数据。

### 证据铁律（两次翻车换来）

1. **「缺失」与「值为 None」必须字面可区分**：缺失写 `<未声明>` + `*_present` 布尔。
   **属性不存在的中间表示不能复用「有值」的值域** —— 曾把 Cookie 缺失读成
   `SameSite=None`，进而写出「Chrome 会拒绝该 Cookie」这类**自我削弱附注**，
   等于替厂商备好驳回理由
2. **改了底层函数 ≠ 修好调用点**：`fetch()` 加了 `follow_redirect` 参数，
   但 `main()` 仍走默认跟随 → 端到端复跑并比对原始输出
3. **urllib 默认跟随 30x**：会把「明文 301」记成「200 不跳转」。判断是否跳转须让
   `redirect_request` 返回 None，再从 `HTTPError.headers` 里取 Location
4. **写前自问：这句措辞在帮我还是在帮厂商？** 真实减分项如实写；误读出来的必须删
5. **多值头会被 `dict(headers)` 静默截断**：一个响应同时下发 `XSRF-TOKEN` +
   `laravel_session` 时，**真正的会话 Cookie 被丢掉**，证据里只剩 CSRF token。
   Set-Cookie 必须单独存多值列表（`_all_set_cookies`），解析优先取它
6. **CSRF token ≠ 会话 Cookie**：会话正则若含泛化 `token`，会把 XSRF-TOKEN 判成会话标识；
   窃取 CSRF token 不能劫持会话，据此论证「会话劫持链」会被一句话驳回。两者正则必须互斥
7. **非 200 不能静默丢弃**：既不产 finding 也不产 negative 会违反「排除必产 negative」，
   且暗示「文件不存在」。≥500 或体积 ≥3× 基线 → 标 `needs_manual_check`（「未取得可判定响应」）
8. **异常响应先取证再下结论**：引擎只记状态码 + 字节数，**无法判断正文是什么**。
   `rmt` 的 500/38659B 直觉是 Laravel 调试页泄露，**实为 WAF 拦截页**
   （`Server: ZS-Proxy21/v201`，正文基本是 base64 内嵌图片）；`qmt` 的 404/11043B
   是站点自身 404 页。**按表象写就是幻觉发现**
9. **前置 WAF 污染状态码判据**：同一路径可能返回拦截页 / 跳转 / 自定义错误页 →
   「未命中」的真实含义是「**未取得可判定证据**」，**不等于**「路径不存在或已防护」，
   这一区别必须写进结论边界，否则覆盖度结论是假的

### 措辞铁律（会直接印进报告和提交稿）

- 规则名 / 发现名**不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测 `{bytes}B`。
  **能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S) +「安全影响」(C/I/A)，
  不写套话

### 测试基建铁律

1. 会写真实配置文件的测试**先备份再还原**（曾删掉真实 `auth.json`）；
   环境隔离 `PENTEST_AUTH`/`PENTEST_SESSIONS` + `tempfile.mkdtemp()`
2. **靶场红时先分辨「数据脏」还是「代码错」**（P3 首跑 6 红里 4 条是数据不合格；
   P4 首跑 6 红里 2 条是 cookie 名写错）。**别改断言迁就**
3. **靶场必须自检 `status=None`**：忘 `verify_tls=False` 会让 HTTPS 全部失败，
   却表现为「站点没内容」→ **假通过**（P2/P4 各踩一次）
4. **禁止用 `python -c`/bash 内联写含反引号的中文长文本**：反引号被 bash 当命令替换执行，
   内容被静默挖空（踩过**两次**）→ 一律用 Write 写 .py 脚本再执行；
   **规则数量别硬编码**，从 `rules.load_rules()` 动态取

### 响应分类与 R014（P1）

- **`base.classify_response()`**（`rules/data/error_pages.json` 120 条）把响应分成
  报错页 / 拦截页 / 拒绝页 / 目录列举。三条硬边界：
  ①**过泛词**（`error`/`line`/`Internal Server Error`/`server at`）只作旁证，
  单独采信 = 抑制器自己变成假阳性来源
  ②**`listing`（`Index of` / `Parent Directory`）是正向证据**（CWE-548），禁止用于抑制
  ③命中后要**写进措辞**（「实测为 WAF/拦截页（waf:创宇盾）」），不写「疑似」
- **非 200 也必须带分类结论**：`/storage/logs/laravel.log` 返 405/1841B 看着像
  「未取得 200 内容」，实为**阿里云统一错误页**（`errors.aliyun.com`）→ 含义是
  「请求在边缘节点就被拦了」，源站有没有这个文件**根本没被判定**
- **跨路径一致性**：多条**不同**路径返回**字节完全相同**的非 200 响应 = 站点通用
  错误页模板，不是路径内容（qmt：`.git/config` 与 `laravel.log` 都是 404/11043B/
  同 sha256）。可据此把「需人工查看响应体」降级，但**不解除**「文件是否存在」的疑问
- **R014（凭据 / 密钥暴露，0 额外请求）**：扫前面规则已取回的响应，排 ORDER 末尾。
  判据必须「敏感名字 + 赋值号 + 引号值」三要素 + 占位符 / 低熵过滤
  （**`\b` 在 `your_api_key` 上不成立**，`_` 属于 `\w`，占位符规则要显式接受
  分隔符 / 数字 / 结尾）。**隐私铁律**：只记类别名 + 次数 + 值的长度与字符集，
  **不记值也不记其哈希**（低熵口令哈希可反查）。与 R008 重叠时以 R008 为准
- **字典库原料「不读就信」是最大风险**：`HTTP/errors.txt` 曾被误判为「WAF 拦截页特征表」，
  读过原文才发现是 **SQL/框架报错串表**；`secret-keywords.txt` 69 行是裸关键词，
  单独使用会命中每一个网页。故构建脚本**强制逐条定性**（漏 / 多 / 重复一律报错退出）

### 通用工程坑（展开）

- **nuclei 必须 `-no-interactsh`**：约 710 个模板回连 `oast.*` 被网关掐断（零输出、无提示）
- 去重两层：`(template_id, matched_at)` + `(类别, 归一化位置)`；`type=generic` 视为未知类别
- **「工具没装」先怀疑调用侧**：中文 Windows 用 `encoding="utf-8"` 会丢输出；
  端口列表别用 `split()`（nmap 会把端口串当主机名）。**耗时 = 超时整数倍 → 参数拼错；
  秒返空 → 编码问题**
- Windows 不能用 `SO_REUSEADDR` 探测端口；nmap 无 Npcap 时 `-sV` 挂起 → 降级 `-sT`；
  Go 版本号先剥 ANSI 色码；`_find_exe` 认 `.bat/.cmd/.py`
- 合规闸统一 **rc=2 + stderr**（`sys.exit(str)` 是 rc=1）；`git ls-files` 非 ASCII
  转八进制 → `-z` + escape_decode；中文名 ENOSYS → `--ignore-errors`

## 十四之二、补天公益 SRC 平台规则（原 MEMORY 独有，2026-09-23 下沉至此）

- **不需核备案、不需事先报备**（「报备」条款只针对专属 SRC / 众测）；
  **无资产白名单**。范围判据 = **官网首页公开链出 + 版权/主体一致**；
  ICP 备案只在提交时作第 2 项「归属证明」用，不作为范围前置条件。
- 红线：禁自动化扫描器 / 禁高并发 / 禁破坏性 / 禁碰用户数据 / 禁范围外 / 禁未授权横向。
  自律：单线程、间隔 ≥6s、单次 ≤10 请求，全部写审计链。
- **提交模板 6 项**：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务。
  其中 ②③⑤ 需人工补（本平台只能供给 ①④⑥）。
- 教训：**平台规则类建议先查官方文档，别靠行业通例推断** —— 曾据「行业通例」推断
  「公益 SRC 要核备案」，与官方文档矛盾。

## 十五、Web 控制台（webui.py）

`python webui.py --host 127.0.0.1 --port 8899`，零依赖（标准库 `http.server`）。
**2026-09-23 之前是 v0.5 基线**：只有 init / plan / autorun(recon,scan) / report /
audit / tools / engage —— 只读规则引擎、lint、coverage 在界面上**完全不可用**，
「平台前端」与「平台能力」是两张皮。本次接入为 ② 卡片「只读规则引擎」。

### 接入时必须处理的三个陷阱

1. **SystemExit 会静默杀死请求线程**（最关键）
   `run_check()` 与合规闸用 `sys.exit(2)` 表达拒绝，而 `SystemExit` 继承
   `BaseException` —— `socketserver.process_request_thread` 只捕 `Exception`，
   异常逃逸到 `threading.excepthook`：**请求线程静默结束、客户端收到空响应**，
   进程不死，问题完全不可诊断。修法：`_capture()` 转成 `(None, log, reason)`，
   并用 `contextlib.redirect_stdout` 把 CLI 的 print 一并捕获成运行日志。
2. **只给退出码 = 用户看不到原因**
   合规闸的写法是 `print(reason, file=sys.stderr); sys.exit(2)` —— 人类可读的
   原因与机器码**分开传递**。只回 `exit 2`，界面就显示「合规闸拒绝（exit 2）」，
   用户得展开日志才知道为什么被拒。`_pick_reason()` 从捕获日志里挑
   `[BLOCK]`/`[FAIL]` 开头的行作为提示（实测已回出「目标 'x' 不在授权范围」）。
3. **界面不得放宽自律下限**
   `interval ≥ 6s`、`max_requests ≤ 10` 在 `api_check` 里**强制钳制**并回显
   `clamps`；CLI 保留专家自由度，界面不做例外 —— 否则「自律」只是纸面。
   测试要用小值时 **monkeypatch `webui.MIN_INTERVAL`**，
   不在生产代码里开环境变量后门。

### 并发

`_CHECK_LOCK` 把规则引擎执行串行化：方法学前提本就是单线程 + 限速，且
`_capture()` 用的是**进程级** `sys.stdout` 重定向，并发请求会互相串台。

### ⚠️ Windows 文件名陷阱（NTFS ADS）

host 带端口时，`f"rules_{host.replace('.','_')}.json"` 会生成含 `:` 的路径 ——
NTFS 把 `:` 之后解释为 **alternate data stream**：文件本体 **0 字节**、证据躺在
隐藏流里，而 `os.path.isfile()` 与 `getsize()` **全部正常**
（实测返回 True / 1854 bytes），`ls` 却显示 0 字节，复制 / 打包 / 提交时内容
直接丢失。已抽 `orchestrator.safe_evidence_name()` 供 CLI 与 Web 共用
（`.` → `_`，保持既有产物命名不变）。靶场两条断言锁住。
**「所有校验都通过、只有人眼能发现」的失效必须从命名层堵掉。**

### 两处已知不一致（未修，已记录）

1. `orchestrator.target_in_scope()` **不剥端口**，而
   `rules_engine.target_in_scope()` 会剥（`t.split(":")[0]`）——
   同一 target 在 init 与 check 两侧判定可能相反。
2. 由此 coverage 的资产匹配也不剥端口：Web 端用 `host:port` 核查后，
   `scope.hosts_missing` 仍把它列为「缺失」（实测 `hosts_missing: ['127.0.0.1']`，
   而该资产其实已跑到）。对补天实战（查域名不带端口）无影响，
   但查 `host:8443` 会误导。**修它要动 coverage 读数语义，需单独评估。**

### 靶场

`_test_webui_lab.py` 122 条：用 `Handler.__new__(Handler)` 跳过 `__init__`
（否则会真的收发 HTTP），直接调 `api_*`。覆盖：范围外拒绝不逃逸 SystemExit /
自律钳制 / 产物并入会话 / 合并语义 / 无会话友好错误 / 证据名净化 /
驾驶舱态势数据口径 / 格式校验与凭证上传 / 前端页面结构 / 离线保证。
**全量回归 12 个靶场 613 条全绿。**

## 十五之二、UI 改造（2026-09-23 · 按《终极美化+交互全量落地方案》）

方案定了 5 大区块 + 强制配色 + 5 条动效 + 4 条交互锁。落地时踩出的关键点：

### ⚠️ PAGE 必须是 raw string（r 前缀），否则前端静默报废

页面是内嵌在 `webui.py` 里的三引号字符串，里面全是 JS。**普通字符串会把
JS 的 `\n` 在编译期解码成真实换行**，把 `'\n'` 这类单引号字面量直接折断 →
运行期语法错；正则里的 `\s`/`\d` 也会被 Python 提前处理（并触发
`SyntaxWarning`）。改为 `PAGE = r"""..."""` 后 JS 原样输出。
**判据要机器化**：断言 `join('\n')` 这个精确子串存在 —— 谁把 `r` 前缀去掉，
它就消失。靶场已锁。

### 拼接超长内嵌页面的做法（别手改 1200 行字符串）

`Edit` 替换整块 PAGE 既笨又易错。做法：把新页面写到临时文件 →
脚本按 `PAGE = r"""` / `</html>"""` 两个锚点切片替换 →
**替换前先 assert**：页面内不得含 `"""`、不得以反斜杠结尾（raw string 收尾条件）。

### 前端也必须有门禁（Python 编译查不到 JS）

`node --check`（提取 `<script>` → `</script>` **之间**的 JS，带上标签会被当成
非法 token）＋ 两条静态一致性断言：
- JS 里所有 `$('#id')` 引用的 id 必须在静态 HTML 中存在（`mk_no`/`mk_yes` 由
  弹窗动态注入，显式白名单）
- 内联 `onclick/onchange` 调用的函数必须都已定义

`_test_webui_lab.py` 里 node 找不到时**明确报 SKIP 并不计入通过** ——
虚门禁比没门禁更危险。

### 视觉验证：无头浏览器 + iframe 偏移裁剪

CLI 截图只能截视口顶部；而 Read 会把大图缩到看不清。做法：
1. 本机 Chrome/Edge 无头：`chrome --headless=new --window-size=900,1500 --screenshot=... URL`
2. **看下半页**：写一个临时 HTML，`<iframe src="URL" style="position:absolute;top:-1450px">`，
   截这个 wrapper —— 等效于任意位置的裁剪，比 CDP 省事
3. 视口取 **900 宽**（≈ 原尺寸，14px 字可读）；1440×3200 那种会被缩到看不清
4. 加锚点 `#id` 会得到「内容贴底 + 上方大片黑」的错觉截图，**别据此判断有布局 bug**

### 驾驶舱数据必须由后端真实状态驱动

`/api/status` 扩展出四组：`metrics`（风险四档）/ `flow`（五步状态）/
`assets`（授权总数·已探测·越界拦截）/ `license`（授权与凭证）。
三条口径纪律：

- **风险四卡片只统计发现项**，排除项一律不计入 —— `needs_follow_up` 表示
  「没取得可判定证据」，算进风险等于把「没查清」当「有洞」。同时返回
  `from_rule_engine`/`from_nuclei` 两个来源计数，让读者知道数字从哪来。
- **严重度必须归一**：规则引擎给 `High`/`Medium`（首字母大写），nuclei 给
  `high`/`medium`（小写）。不归一 → 四卡片分裂计数。
- **越界拦截数只认「真实被拦截的动作」**（审计链里 action 含 BLOCK/REJECT），
  不认「点了几次校验按钮」：`api_scope_check` 是纯校验、零副作用、不写审计，
  否则一个格式检查按钮就能把风险数字刷上去，指标失去意义。靶场两条断言锁住
  「零副作用 + 不虚增」。

### 阶段0 两个新动作

- `POST /api/scope_check` —— 格式校验。合法性判据 `_scope_item_kind()` 刻意与
  `orchestrator.target_in_scope` 的三种匹配方式（CIDR / `.域名` 后缀 / 精确或子域）
  对齐：**前端若自造一套格式规则，就会出现「前端绿标通过、后端闸门拒绝」的假绿灯，
  比不做校验更危险**。含端口条目判「合法但 warn」—— 把上面那处未修的不一致
  直接摆到用户面前。
- `POST /api/auth_doc` —— 授权凭证上传（PDF/图片，原始字节）。
  落盘文件名**完全由服务端生成** `<会话id>.authdoc.<白名单后缀>`，
  用户文件名只作元数据存进会话 → **不参与路径拼接，穿越面为零**；
  后缀白名单 + 5MB 上限。审计记 sha256 前 16 位。

### 交互锁（方案八·1）

`data-need="session|plan|unlock"` 声明式挂锁 + `applyLocks()` 统一求值；
`BUSY` 期间全部动作按钮禁用、运行按钮加 `busy` 脉冲类。
**未建会话时遮罩只盖 `#gated`（流程导航+阶段1+阶段2），不盖阶段0** ——
门禁卡是唯一入口，盖掉它就没法解锁了。

### 与方案的一处刻意的偏离

方案 §八.4 要「完成弹窗」。实现用 **Toast + 流程导航 + 终端**，不给每次完成
弹模态框：模态框在每次成功时弹出，用户会训练成无脑点掉，等到真正需要确认的
高危动作时也照点 —— 这会削掉 §八.2 那四个强制确认弹窗的效力。
**强制确认只留给不可逆动作，成功反馈用非阻断的。**

## 十五之三、UI 第二轮（2026-09-23 · 8 级层级 / 视觉规范 / 交互 / 合规）

第二轮方案（布局信息结构 / 视觉美化 / 交互体验 / 细节微优化 / 合规专项）
把界面推到 8 级信息层级，并把原「阶段1 驾驶舱」**拆成 4 张独立卡片**：
顶部态势 → 合规授权入口 → 流程导航 → 漏洞统计概览 → 任务操作区 →
授权资产列表 → 实时日志 → 高危利用模块。

### ⭐ 进度与门禁必须分开建模（本轮最重要的设计决定）

流程导航节点同时承载两件事：**走到哪了**（进度）和**能不能进**（门禁）。
第一版把「前置未满足」也写成 `state="locked"`，于是
**「没做过」和「做了被锁」在数据上无法区分** —— 与本项目在闭环纪律里反复
防的那类语义塌缩是同一个病。改法：后端同时给

- `state ∈ pending / running / done / locked` —— 进度，**刻意不撒谎**
- `gate ∈ true/false` + `need "<缺什么>"` —— 能否进入
- `hot`（高危节点，前端据以上橙色）—— 危险程度也是独立维度

前端 `gated = (gate === false) || (state === 'locked' && !已解锁)`。
**三个维度拆开之后，任一维度的语义变化都不会污染另外两个。**

### ⚠️ 后端字段缺失会让前端印出「假事实」

前端曾写「排除项 `m.excluded` 条不计入风险」，但 `_risk_metrics` 根本没返回
`excluded` → JS 里 `undefined || 0` 得到 0 → 页面稳定显示**「排除项 0 条」**。
这与会话里真实有 128 条排除项矛盾，且**没有任何报错**。
**通则：前端引用的每个后端字段，都要么在靶场里断言其存在，要么在界面上
显式区分「无此项」与「值为 0」**（同 §七 证据铁律第 1 条）。

### ⚠️ 内联 onclick 不能传 `JSON.stringify` 的值

`onclick="flow_goto('init',` + JSON.stringify("pending") + `)"` 会生成
`onclick="flow_goto('init',"pending")"` —— 双引号提前闭合属性，整段 JS 报废。
**做法：内联只传 key，其余字段从全局状态反查**（`ST.flow`）。

### ⚠️ 主题标签必须随持久化一起同步

浅色偏好存 localStorage，但按钮文案只在 `toggle_theme()` 里改 →
刷新后「页面是浅色、按钮还写 🌙 深色」。抽出 `sync_theme_btn()`，
启动时与每次切换都调用。**任何「状态变了但标签没跟着变」的地方都是同类 bug。**

### 浅色主题怎么验证（而不是靠看）

`file://` 打开页面副本注入 `body.classList.add('light')` 只能验配色 ——
跨源 `fetch('/api/status')` 会被 CORS 拦，数据绑定是空的。
要看**带真实数据的浅色界面**：临时复制一份 `webui.py`，把 `<body>` 改成
`<body class="light">`，起在另一个端口指向同一会话目录，截完即删。
**不改生产代码，也不靠「应该没问题」。**

### ⚠️ 无头 Chrome 单层渲染高度上限约 4096px

`<iframe height="5400">` 做偏移裁剪时，**超出上限的部分不绘制**，
截出来是纯背景色 —— 极易被读成「布局空白 / 页面崩了」。
控制在 **≤3500px**，并留意：三张截图字节数完全相同（如都是 6156）就是
「全都没渲染出来」的信号，不是「内容恰好一样」。

### ⚠️ 这个 shell 里 `curl -w %{size_download}` 不可信

配合 `-o /dev/null` 时它报了 **恰好 65536** 字节，而真实页面是 85726 字节，
一度让人以为服务端在 64KiB 处截断了响应。**校验完整性要落到文件**：
`curl -o _s.html URL` + `wc -c` + 检查 `</html>` 是否存在。

### 其余落地要点

- **12 栅格**：`.grid12{grid-template-columns:repeat(12,1fr)}` + `.c3/.c4/.c6`
  跨列；边距 24px、卡片间距 20px、卡片内边距 20px、组件 16px、表单 12px
- **长列表**：`.tblwrap{max-height:...;overflow:auto}` + `th{position:sticky;top:0}`
  —— 固定表头靠 sticky，不是靠双 table 对齐（后者列宽必然漂移）
- **弹窗三类**：`tone ∈ info/risk/danger`；`danger` 且带 `requireText` 时
  必须**手输「确认风险」**才解除确认按钮禁用
- **一键复制**：`navigator.clipboard` 不可用（非 HTTPS / file://）时回落
  `execCommand('copy')`，两条路都要给 Toast 反馈
- **终端**：「暂停滚动」只停自动滚动（日志仍在记录），「清空」只清本窗显示
  —— 界面必须明写「审计链 append-only 不可删除」，否则等于暗示可以删证据

### 配色上的一处如实取舍

方案要求「固定色值，不随意新增颜色」。四档严重度（高/中/低/信息）无法只用
3 个语义色 + 灰映射而不撞色，故低危沿用 `#FFD666`，**并严格守住红/橙的语义**：
红只用于法律警示与阻断，橙只用于利用模块与中危。**这是取舍，不是遗漏。**

## 十五之四、UI 第三轮（2026-09-25 · 方案 B+C：作战概览 + 左导航）

### 方案 B — 信息密度
- **流程导航 + 漏洞统计合并为「作战概览」单卡**（`#flow` 嵌入 `#stats`
  内部，`阶段进度` / `风险分布` 两个 `.grp` 小节）。`.flow` 由独立卡壳
  （自带 border/shadow/margin）改为嵌入式面板（deep 底 + padding:14px）
  —— **嵌进卡片时必须剥掉原来的卡壳样式**，否则双层边框双层阴影
- 任务操作区收敛为「主流程 / 合规检测」两行；次级功能降为 `.card-ft`
  卡底 footer（带 `次级功能` hint 字样），视觉权重降级但功能一个不少

### 方案 C — 导航结构
- `.wrap` → `.layout{display:flex}`：左侧 `.sidenav`（186px，
  `position:sticky;top:76px`）+ 右侧 `<main class="main">`
- 导航 6 项对应 6 张卡（`data-t` 定位，**不带 id= 前缀**，避免撞顺序断言）；
  `nav_goto(id)`：滚动定位 + **DETAILS 自动 open**（资产/日志/利用导航即展开）
- `IntersectionObserver` 滚动联动高亮（`rootMargin:'-40% 0px -55%'` 视口带）；
  `paintNav()` 门禁徽标（未授权/已授权）随 `refresh()` 同步
- 窄屏 ≤960px：`.layout` 纵向堆叠、侧栏折叠为**横向滚动条**（导航换形态
  而不是消失）

### 合规边界（B+C 均适用）
- **左导航只是定位手段**：gatemask / 高危 veil / data-need 锁照常挡在
  内容前面，导航不持有任何解锁逻辑
- 测试顺序断言同步改为 `gate < stats < flow < ops < assets < logs < expo`
  （flow 嵌入 stats 后字符串顺序变化）—— **改嵌套结构必须同步改顺序断言**

### 追加：方案 D（2026-09-25 · 门禁卡授权后瘦身）

- 授权会话创建后，`#gate_form`（4 输入 / 资产校验 / 凭证上传 / 书面授权
  勾选 / 创建按钮）自动收起，卡片只剩：**法律警示条（在收起容器之外，
  永久展示）+ 绿色授权摘要 + 「修改授权信息」展开按钮**
- `paintGateForm()` 在 `refresh()` 里同步；`GATE_EDIT` 全局开关由
  `gate_edit()` 切换、`init_()` 成功后复位 false（下次 refresh 重新收起）
- **合规边界**：收起只降信息密度 —— 未授权时表单照常全量展示；重建会话
  仍走完整失焦校验 + 格式校验 + 确认弹窗 + 审计链；`#legal` 必须在
  `#gate_form` 之外（有专门断言钉死这个位置关系）
- 效果：授权后整页高度 ~2500px → ~950px，首屏直接看到作战概览全貌

### 追加：方案 E+F（2026-09-25 · 说明压缩 + 去双导航）

- **E**：合规检测组 5 行方法学说明压成一行（只留「非扫描器 / 与只读侦察
  并列入口」两个行为要点），**全文原样移入 `details.adv` 参数面板首部**
  —— 压缩 = 移位置，不是删信息；要保留的判定信息先找新家再压
- **F**：删除 `flow_goto` 与流程节点 `onclick`（**双导航收敛为侧栏单导航**）；
  节点保留 `title` 悬浮提示（`s.need` 缺什么）与 `.hn` 前置文字，仅去
  `cursor:pointer` —— 状态条仍完整表达 进度(state)/门禁(gate)/危险度(hot)，
  只是不再承担定位职责
- 教训：**同一交互能力有两处入口时，删一处必须同步删函数与测试断言**；
  `flow_goto` 移除后测试改为负断言（`"function flow_goto(" not in page`）
  防止死代码回潮
- 回归 **12 靶场 714 条全绿**（webui 218 → 221）；e2e 靶场输出的 `[FAIL]`
  是合规闸自身日志行（升级需证据提示），`exit=0` + 全 PASS 为准

## 十五之五、Dashboard 重构（2026-09-25 · 视图切换 + 概览 7 卡）

### 结构
- 主区改 **5 视图切换**（`.view`/`.view.on`）：dash / ops / assets / logs / expo；
  左导航从「滚动定位」升级为**页面切换器** `showView(id)`（IntersectionObserver
  滚动联动随之删除）；12 栅格：`.sidenav` span 2 / `.main` span 10
- 概览页 7 卡：卡0 门禁通栏（状态/目标/会话 + 精简法律提示 + `展开详情`
  折叠完整协议/合规开关 + 修改授权信息）；卡1 阶段进度导航（**6 节点**，
  新增「报告归档」）；卡2 风险指标四卡；卡3 任务总览（只读）；卡4 资产总览；
  卡5 审计预览（`AP_MAX=5`，term() 同步克隆行）；卡6 高危模块状态
- **概览页禁止执行按钮**（测试取 `v_dash` 子串断言无 `data-need=`/autorun/check_/plan_/engage_）；
  资产/审计/高危由 `details` 折叠卡转为独立页 `<section>`（视图即页面，
  折叠语义已无意义）；`.assetal` 内层折叠保留
- 后端：`_flow_steps(sess, audit_rows)` 增第 6 节点 `report` —— 审计链出现
  REPORT 动作即 done；`api_report` 查看报告时写审计 `REPORT`（报告访问本身
  可审计，同时驱动节点状态，前端无法伪造）

### 踩坑
- **删元素时把别人还在用的变量一起删了**：去掉 `gate_ok` 块时连带删了
  `var ok = !!s;`，但授权摘要块仍引用 `ok` → ReferenceError 使 refresh 中断、
  `applyLocks()` 没跑、遮罩不消失。**静态断言查不出运行时引用错** ——
  用 `chrome --dump-dom --virtual-time-budget` 看 DOM 实际更新到哪一步定位
- 改完源码**必须重启预览进程**：PAGE 编译期进内存，热改文件不影响在跑的服务
  （曾对着旧进程连截两张「没修好」的图）
- e2e 里 `[FAIL]` 是合规闸自身日志行（升级需证据提示），以 `exit=0` + 全 PASS 为准

## 十六、人工复核记录必须按「位置」存放（2026-09-30 · DXYSRC 提交稿暴露）

### 缺陷两条（都已实际发生，都会直接损坏提交可信度）
1. **多位置复核互相串稿**：`_verify_rule` 曾 `ver[rule_id] = {...}` 单条存放 ——
   先复核 A 位置、再复核 B 位置，**B 覆盖 A**（只有一份 `evidence`）。提交稿里
   `act.biomart.cn` 条目印出的是 `xiaoyuan.jobmd.cn` 的复核取证。
   → 厂商按稿复核会对不上，驳回的同时损耗提交者信誉。
2. **升级一处连带全组进稿**（更危险）：所有消费方都按 `rule_id` 取 `level` →
   复核 A 位置后，**同规则未复核的 B/C/D 也一起被标 `confirmed`** 进入提交稿 /
   SARIF / 报告表格。等于把没验过的当验过的交出去。

### 契约
```
session["rule_verifications"][rule_id] = {
    "scope": "location" | "group",
    "records": { "<站点>|<归一化路径>": {level, evidence, note, host,
                                        location, rule_id, verified_at, scope} },
    "locations": [...]   # 历史已复核位置的**并集**（逐条复核不该抹掉前一条痕迹）
    "updated_at": ...
}
```
- **顶层刻意不写 `level`/`evidence`**。任何遗漏改造的旧消费方
  `.get("level", "detected")` 会回落到「疑似」——**失败方向安全**：
  宁可不提交，也不能把没复核的当已复核。
- 查询唯一入口 `cvss.find_verification(verifications, rule_id, host, location)`；
  未登记的位置**直接返回 `None`，不退回规则级**（那正是串稿来源）。
- 旧格式（顶层有 `level`、无 `records`）只作历史兼容读取 → `has_legacy_verification()`
  为真时 `submit` **明写告警**「旧格式、位置不精确，请逐条重登记」。

### 键的构造（`cvss.norm_verify_key`）—— 两个必须都在键里
- **站点**：`_norm_location` 会把 URL 剥成纯路径，于是
  `https://act.biomart.cn/` 与 `https://xiaoyuan.jobmd.cn/` **都归一成 `/`**。
  只按路径做键，两站同规则同路径必然互串。
- **路径**：查询串剥离、大小写不敏感、`/.env` 与 `https://h/.env` 必须同键。
- `location` 本身是 URL 时**以其 host 为准**，否则退回传入的 `rule_checks` 键 ——
  两种数据形态都存在：真实规则引擎给的是相对路径（站点来自 `rule_checks` 键），
  导入/靶场数据给的是完整 URL 且主机可能与 `rule_checks` 键不同。只取一个都会折叠错。
- 空位置（`"host|"`）与根路径（`"host|/"`）必须分开。

### 消费点清单（改存储/查询时必须全部跟）
`orchestrator`：submit 置信度判定、`_submission_block` 复核段、report 表格置信度、
report 明细复核行、SARIF `report --format sarif`；
`evidence_lint.lint_result`（EL007 豁免粒度 —— 曾只按规则回放，把未复核位置的
EL007 阻断项一起豁免掉）。
`verify --host <主机>`：同规则同路径出现在多台主机时用于消歧（只按 `--location`
会一次命中多台主机，这是串稿的入口之一）。

### 迁移范式（不要重新发请求）
证据原文完整躺在 `.sessions/<id>.audit.log` 的 `RULES-VERIFY` 事件里
（格式：`规则发现 <RID> @ <loc> 置信度升级为 <level>（n 条） —— <evidence>`）。
写脚本从审计链抽回原文、按位置重登记 —— 这是**存储迁移，不是新取证**，
不该、也不需要重新发一次请求。迁移后必须 dump 校验：`scope=location`、
顶层无 `level`、记录数 == 位置数、每条 `evidence` 含本机主机名。

### 顺带修掉的相邻缺陷（同一轮 DXYSRC）
- **R001 CSP 假阳性**：旧判据要求值里含 `*-src` → `Content-Security-Policy:
  frame-ancestors ...` 被误判「语法非法」。改 `_csp_problem()` 按**指令列表**校验
  （`frame-ancestors`/`sandbox`/`report-uri` 合法；裸 scheme 缺冒号才非法）。
- **证据被 `val[:80]` 截断**：真实值 `...lctest.cn:* https://identity-app.linkedcare.cn:* ...`
  被截成 `...lctest.cn:* http` —— **尾部被伪造成一个疑似非法 token**，等于自己造了一条
  不存在的证据。证据字段一律存完整值，只在展示处截。
- **R009 缺 counterevidence**：框架指纹给了「使用含已知漏洞的组件」中危，
  但只有指纹没有版本 → 违反 D-01。补 `counterevidence`：只能证明用了该框架，
  不证明版本受影响。

### ⚠️ 两个「本地全绿、真跑才崩」的工具坑
1. **追加式补丁脚本不幂等**：`new` 完整包含 `old`（在 `--location` 后插 `--host`）时，
   `count(old)==1` **不足以保证安全** —— 重跑一次就再插一遍。实测被插 **3 份**
   `--host` → `argparse.ArgumentError: conflicting option string: --host`
   **整个 CLI 起不来**，而所有函数级单测全绿（它们直接构造 args、不走 argparse）。
   幂等判据必须**先查 `new` 是否已存在**。
   → 对策已固化：`_test_verify_location_lab.py` ⑥ 段自动发现全部子命令并逐个跑
   `--help`（16 个），专抓 argparse 冲突。
2. **CRLF 让补丁静默失效**：本仓 765 个 `.py` 是 LF、**8 个是 CRLF**（历史写入工具
   留下的）。按字节匹配时 CRLF 文件上 `count(old)==0` → **脚本报成功但补丁没打上**。
   → 补丁脚本统一 `newline=None` 读（归一成 `\n`）、`newline="\n"` 写；
   `.gitattributes` 加 `*.py text eol=lf` 并把那 8 个文件规范化。
3. **子进程输出跨编码**：Windows 子进程 stdout 走控制台代码页（cp936），父进程
   `text=True` 按 utf-8 解会 `UnicodeDecodeError: 0xd7`。→ 子进程给
   `PYTHONIOENCODING=utf-8`/`PYTHONUTF8=1`，父进程 `encoding="utf-8", errors="replace"`。

## 十七、提交记录

fd24fc2 03f97bf 06f16d8 d9b908e e2afe00 ec6d98e 1b0f4e2 4d42efa 5ddf1ee 326682d 10b8f71（R013）fb04a82（strix 第 2、3 项：机器观测层 + 排除判据库）· a0dca4b（记忆分层：详情下沉 HANDBOOK、状态拆出 LEDGER）
b65074c（修 webui scan 分支 `payload` 未定义必崩点）· 82a6592（只读规则引擎接入 Web 控制台）
7be3932（补齐提交记录）· 9ec52ea（UI 第一轮：5 大区块 / 强制配色 / 5 动效 / 4 交互锁）
612b451（UI 第二轮：8 级信息层级 / 视觉规范 / 三类弹窗 / 合规强化）
db18b91（补齐提交记录）· d14c375（MEMORY 超限瘦身 + 补天 SRC 下沉 十四之二）
74c6f66（UI 简化 A：三详情卡折叠 / 参数面板 / 顶栏收敛）· 1cace1f（UI 方案 B+C：作战概览合并卡 + 左侧阶段导航）
a6db8b0（UI 方案 D：门禁卡授权后瘦身）· f7cc1ec（UI 方案 E+F：长说明压缩 + 流程节点改纯状态）
609f626（Dashboard 重构：视图切换 + 概览 7 卡 + 第 6 节点报告归档）
2d70005（.gitignore 忽略真实目标取证产物）
74c6f66（界面简化 A：详情卡收起 + 参数折叠 + 顶栏收敛）· 8fa7d15（补记录）
1cace1f（UI 第三轮方案 B+C：作战概览合并卡 + 左侧阶段导航）
