# 自动挖洞平台 - 方法学手册（MEMORY.md 的详情层）

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

## 六、覆盖度量化

`coverage.py` + `orchestrator coverage`。靶场 62/62。
**必须拆两个数**：`score` 核查完成度（相对当前方法学可达范围，多跑就涨）/ `ceiling` 方法学上限（匿名 + 只读 + conservative = **20%**，结构性）。
**刻意不把 ceiling 计入 score**：否则匿名只读永远不及格 → 分数失去区分度。结构性限制单列：不掩盖，也不污染可改进项。
五维度权重：资产 0.30 / 规则 0.25 / 完整性 0.15 / 栈定向 0.15 / 证据质量 0.15。`绝对覆盖度 = score × ceiling / 100`。
分母：资产取 `in_scope`（`out_of_scope` 不混入）；规则 = 全量 − 需写探测且未开启的；无证据时证据维度 = 0；有 `unfinished` → 完整性 50% + blocker gap。
**副产品：改进收益排序** `gain=(1-score)×weight×100` 降序。直觉以为「1/3 资产」比「1/8 规则」缺口大，实际规则 21.9 > 资产 20.0 —— **边际收益必须算，不能猜**。

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

## 十一、提交记录

fd24fc2 03f97bf 06f16d8 d9b908e e2afe00 ec6d98e 1b0f4e2 4d42efa 5ddf1ee 326682d 10b8f71（R013）
