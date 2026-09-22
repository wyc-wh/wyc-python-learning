# 项目记忆 - 自动挖洞平台

## 一、骨架

- `pentest-orchestrator/`：`orchestrator.py`(CLI) / `rules_engine.py` / `rules/` / `scanners.py`(nmap+nuclei) / `cvss.py` / `exploit.py` / `manual_probe.py` / `coverage.py` / `evidence_lint.py` / `credentials.py`
- 子命令：`init plan autorun engage verify report status check lint submit coverage`
- 合规闸：授权确认 + 范围校验 + `auth.json`(4项) + append-only 审计 + 破坏性阶段禁用 + `allow_scanner=false` 硬开关
- 置信度三级：`detected 🔍`→`confirmed ✅`→`exploited 💥`。**detected 不得提交 SRC**
- **回放**：`rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS：`compute_cvss31(8参)` / `compute_cvss40(11参)`。**4.0 的 UI 只有 N/A/P（3.1 UI:R → 4.0 UI:P）**。一律用引擎算
- 工具：nmap 7.92 / nuclei v3.11.1 / ffuf / gobuster / feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f。缺 nikto/whatweb/hydra/john

### 通用工程坑
- **nuclei 必须 `-no-interactsh`**：约 710 模板回连 oast.* 被网关掐断（零输出无提示）
- **去重两层**：`(template_id,matched_at)` + `(类别,归一化位置)`；`type=generic` 视为未知类别
- **「工具没装」先怀疑调用侧**：中文 Windows `encoding="utf-8"` 丢输出；`split()` 用在端口列表会让 nmap 把端口串当主机名。**耗时=超时整数倍 → 参数拼错；秒返空 → 编码问题**
- Go 版本号先剥 ANSI 色码；`python -m <pkg>` 不万能；`_find_exe` 认 `.bat/.cmd/.py`
- **Windows 不能用 SO_REUSEADDR 探测端口**；合规闸统一 **rc=2 + stderr**（`sys.exit(str)` 是 rc=1）

## 二、补天公益 SRC 规则

- **不需核备案、不需事先报备**（"报备"条款只针对专属SRC/众测）；**无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只在提交时作第 2 项「归属证明」
- 红线：禁自动化扫描器、禁高并发、禁破坏性、禁用户数据、禁范围外、禁未授权横向
- 自律：单线程、间隔 ≥6s、单次 ≤10 请求，全部写审计链
- **提交模板 6 项**：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务。②③⑤ 需人工补
- 教训：**平台规则类建议先查官方文档，别靠行业通例推断**

## 三、手工只读核查手法（命中率降序）

`manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`（仅 GET / ≥6s / ≤6 请求）

1. **⭐ 版本 → 厂商官方公告受影响范围（§四）**
2. **抓首页 href 的 host** 找业务系统 —— 比 crt.sh 有效
3. **客户端安全控制绕过**：见"正在验证您是否是真人"读 JS；若只是 `document.cookie=`+reload、服务端不校验 → 一条 curl 头绕过（CWE-602）
4. **后台入口常不在前台防护范围内**：`admin.php` 单独查
5. **弱口令可行性**：搜 `seccode/验证码/captcha`，有就别碰
6. **软 404 用 sha256 比对**：200 但与首页同 hash = catch-all
7. **明文 HTTP 分资产测**：有 HSTS ≠ 80 端口跳 HTTPS
8. **归属证明取首页页脚**；SPA 站去 `app.<hash>.js` 搜「版权所有/京ICP/有限公司」
9. **版本排除法**：先查修复版本，别硬套 CVE
- **零破坏探测写鉴权**：`DELETE /api/xxx/999999999`（不存在的ID）。返回"未登录"=安全；"成功"/404=鉴权缺失
- **「无测试账号」= 教育/政务类 SRC 硬阻塞**，必须提前说明预期。严禁注册真实手机号、严禁测短信频控

## 四、⭐「版本命中官方公告」打法

**困境**：SRC 不许爆破，"无限爆破风险"怎么证明？
**解法**：拆成两条可只读取证的事实 —— ①版本落在厂商官方公告的受影响区间 ②站点未部署官方认可的缓解措施。两条成立即 confirmed，**不需要真爆破**。

实例 F-10（7.4/7.7）：`bbs.ikuai8.com` 页脚+meta 双处取证 `Discuz! X3.3` → 官方公告【2021】第 1 号**明文点名「X3.3 全部 Release」**，官方定级高，**已 EOL 无补丁** → 站点侧实测后台无验证码/人机验证可绕过/明文可达。

要点：查 CVE 更要查**厂商官方公告**（国内 CMS 以公告为准）；版本清单逐条比对确认**被点名**；记下修复版本与 EOL。公开研究可作"风险升级说明"，**标注未验证**。
- **⚠️ 版本命中 ≠ 漏洞成立**：必须再查公告的**触发条件**。Discuz! 公告【2021】第1号
  明写「安装时默认不触发，需管理员在 UCenter 保存设置使 login_failedtime=0 才触发」——
  只报版本命中会被『默认不触发』一句话驳回。已写进 `vuln_components.json` 的
  `_trigger_condition`/`_trigger_probe`。补证：用**不存在的用户名**发一次登录失败，
  提示恒为「还可尝试 4 次」即触发（单次，非爆破）。
- 公告的「修复版本」要核对属于哪份公告 —— 曾把 10 月公告的 X3.4 Release 20211124
  错当 6 月公告的修复版本（后者是「2021-06-29 及以后」）
定级：CWE-307 + CWE-1104，`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

## 五、只读规则引擎（核心能力）

`rules/` + `rules_engine.py` + `check`。**不是扫描器**：无 payload/不遍历/不并发/只 GET/HEAD → **不受 allow_scanner 闸约束**，但强制范围校验 + 限速 ≥6s + 请求预算 + 审计链。
置信度恒为 **detected**，绝不自动 confirmed；**排除必产 negative**；预算耗尽标 `unfinished`。

R001 安全头占位符 / R002 客户端绕过 / R003 明文+Cookie / R004 后台入口 / R005 版本命中公告 / R006 catch-all 基线(抑制器) / R007 零破坏写探测(默认关) / R008 敏感文件 / R009 框架指纹 / **R010 凭据有效性** / **R011 双态鉴权差异**
`ORDER` 中 R006 先跑（基线），R002 先于 R005（绕过后的页面才有版本信息）—— **编排顺序本身就是检测能力的一部分**。
**关联分析比单条重要**：COR-T01(R001∧R003)=6.8；COR-A01(R004∧R005)=7.4。用 `supersedes` 避免重复提交。
- **R012（无账号打访问控制）**：从站点自身公开的 JS bundle 提路径（不遍历不猜），
  匿名 GET 返回 200 + JSON + 有业务字段 → 未授权访问。敏感路径 7.5 / 其余 5.3。
  硬前提：**bundle 必须匿名可达** —— 前端在认证墙后的站（如 jiaoyu）结构性失效
- **证据只存结构不存值（隐私铁律）**：API 响应可能含个人信息。只记字段名、条数、
  sha256、content_type，**绝不记录返回值**。确认时自行 curl 看，别把数据贴进报告

### 实现要点（复用时避开）
- **缓存 key 必须含请求头**：只按 (method,url) 会吞掉 R002 的第二次请求（漏报不报错）。也因此登录态/匿名态天然隔离
- **`OpenerDirector.open()` 不接受 `context=`**：关 TLS 校验要 `build_opener(HTTPSHandler(context=ctx))`
- **`Powered by <a>X 3.3</a>` 正则里 `<...>` 必须整体可选** `(?:<[^>]*)?`
- **根路径跳 HTTPS ≠ 后台也跳**：R003 需对后台入口二段复检
- **靶场用协议嗅探单端口同时服务 HTTP/HTTPS**（首字节 0x16 = TLS ClientHello）

## 六、链路（P0）

`check → verify --rule → report → submit`
- `session["rule_checks"][host]` = check 结果（**合并语义**：本轮 rule_id 覆盖旧的，未跑到的保留）；`session["rule_verifications"][rule_id]` = 人工复核升级
- `check --import-file` 零请求导入；report/verify/submit 均支持 `--session`

### 措辞铁律（会直接印进报告和提交稿）
- **规则名/发现名不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测字节数 `{bytes}B`。**能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S)+「安全影响」(C/I/A)，不写套话

## 七、证据完整性铁律（两次翻车换来）

1. **「缺失」与「值为 None」必须字面可区分**：`cookie_flags` 用 None 表缺失 → 下游读成「SameSite=None」并写出"Chrome 会拒绝"——**自我削弱附注**，等于替厂商备好驳回理由。修：缺失写 `<未声明>` + `*_present` 布尔。**通则：属性不存在的中间表示不能复用"有值"的值域**
2. **改了底层函数 ≠ 修好调用点**：`fetch()` 加了 `follow_redirect` 但 `main()` 仍默认跟随 → 端到端复跑并比对原始输出
3. **urllib 默认跟随 30x**：会把「明文 301」记成「200 不跳转」。判断跳转须 `redirect_request` 返 None，再从 `HTTPError.headers` 取 Location
4. **写前自问：这句措辞在帮我还是在帮厂商？** 真实减分项如实写；误读出的必须删
5. **多值头会被 `dict(headers)` 静默截断**：同名头只保留第一条。一个响应同时下发
   `XSRF-TOKEN` + `laravel_session` 时，**真正的会话 Cookie 被丢掉**，证据里只剩 CSRF token。
   Set-Cookie 必须单独存多值列表（`_all_set_cookies`），解析优先取它
6. **CSRF token ≠ 会话 Cookie**：会话正则含泛化 `token` 会把 XSRF-TOKEN 判成会话标识；
   窃取 CSRF token 不能劫持会话，据此论证「会话劫持链」会被一句话驳回。两者正则必须互斥
7. **非 200 不能静默丢弃**：既不产 finding 也不产 negative 会违反「排除必产 negative」，
   且「无 200 且命中特征者」暗示文件不存在。要区分「未取得可判定响应」
   （≥500 或体积 ≥3× 基线 → 标 `needs_manual_check`）

### 取证纪律：异常响应必须先取证再下结论

引擎只记状态码与字节数，**无法判断响应体究竟是什么**。看到异常大响应（500/38KB、404/11KB）
必须先发一次 GET 看正文再定性 —— 两次实战都推翻了表象：
`rmt` 的 500/38659B 直觉是 Laravel 调试页泄露，**实为 WAF 拦截页**（`Server: ZS-Proxy21/v201`，
正文基本是 base64 内嵌图片）；`qmt` 的 404/11043B 是站点自身 404 页。按表象写就是幻觉发现。

**目标前置 WAF 会污染状态码判据**：同一路径可能返回拦截页 / 跳转 / 自定义错误页。
故「未命中」的真实含义是「未取得可判定证据」，**不等于**「路径不存在或已防护」。
这一区别必须写进结论边界，否则覆盖度结论是假的。

## 八、证据自检 lint（P1）

`evidence_lint.py` + `orchestrator lint`。靶场 37/37。
**存在理由**：两次翻车共同结构是**取证层取值正确、表述层结论错误**，单测抓不到。
17 条断言（EL001-EL029），离线不发请求。最巧三条：**EL004** 证据 sha256 与请求流水里另一 URL 相同 → 跟随跳转；**EL009** 自我削弱措辞（§7.4 机器化，引述语境豁免）；**EL002** `*_present=False` 却写成「属性=某值」。
接入五处（缺一处门禁就是虚的）：`run_check` 出口 / `check --strict` / `lint --file|--session` / `report` 小节 / **`submit` 门禁**（阻断项默认不出稿，`--force` 才出且留痕）。
**结论文本与修复建议必须分开检查**：`remediation` 里「应设为 SameSite=None」是建议值，计入会误报。

## 九、框架指纹（P2）

`rules/data/stacks.json`（14 栈）+ R009。靶场 20/20。
**要解决的问题**：R001~R008 全是通用配置检查，命中率有天花板 —— 缺「这站是什么栈、该栈高发什么」。
三条硬边界：①**指纹识别 0 额外请求**（复用 R006 基线 + R002 绕过缓存）②**定向探针默认不跑**（仅 `--deep`，每栈 ≤4，全 GET）③**`_never_probe` 永不自动请求**（ThinkPHP invokefunction / SpringBoot actuator heapdump / Jenkins script）
**刻意不写 CVE 编号**：只给官方公告入口 + 风险类型，命中后 `needs_manual_check=True`。臆造 CVE 明令禁止。
可靠度 high/medium/low，**low 不单独采信**；**同栈多命中取可靠度最高，不是第一条**（曾把 qmt 的 XSRF-TOKEN(medium) 当首选而漏 laravel_session(high)）。
实战：bbs.ikuai8 → Discuz!(body,high)；qmt.jiaoyu → Laravel(cookie,medium)。Discuz 只在带 R002 绕过时才命中。

## 十、覆盖度量化（P3）

`coverage.py` + `orchestrator coverage`。靶场 62/62。
**必须拆两个数**：`score` 核查完成度（相对当前方法学可达范围，多跑就涨）/ `ceiling` 方法学上限（匿名+只读+conservative = **20%**，结构性）。
**刻意不把 ceiling 计入 score**：否则匿名只读永远不及格 → 分数失去区分度。结构性限制单列：不掩盖，也不污染可改进项。
五维度权重：资产 0.30 / 规则 0.25 / 完整性 0.15 / 栈定向 0.15 / 证据质量 0.15。`绝对覆盖度 = score × ceiling / 100`。
分母：资产取 `in_scope`（`out_of_scope` 不混入）；规则 = 全量 − 需写探测且未开启的；无证据时证据维度 = 0；有 `unfinished` → 完整性 50% + blocker gap。
**副产品：改进收益排序** `gain=(1-score)×weight×100` 降序。直觉以为「1/3 资产」比「1/8 规则」缺口大，实际规则 21.9 > 资产 20.0 —— **边际收益必须算，不能猜**。

## 十一、登录态建模（P4）

`credentials.py` + R010/R011 + stacks.json 的 `auth_paths`。靶场 44 条。
**存在理由**：匿名态下 auth 因子 0.5，所有需登录的功能点/越权/业务逻辑不可见。有测试账号则 ceiling 翻倍（20%→40%）。
**凭据值零落盘**（最硬边界）：证据/审计/会话/报告里**只有 fingerprint 与 cookie 名**，`Identity.as_dict()` 是唯一落盘出口。请求流水记 `anon|<指纹>`。凭据文件进 .gitignore。**不提供「用账号密码自动登录」**（必触验证码/短信，且易滑向口令爆破）。
**R010 必须先于 R011**：凭据无效时 R011 双态一致会得出**假的阴性**（漏报）而非「没法判断」。两种判据：①响应差异 ②**Set-Cookie 差异**（不可省 —— 很多站首页两态同内容，只靠①会全判 inconclusive，而它们恰恰可能藏着最严重的鉴权缺失）。
**R011 三重假阳性抑制**：catch-all 兜底 / 登录错误页 / **首页 `/` 排除**。凭据 invalid/inconclusive 时**拒绝下结论**。
三个真 bug：①登录页正则别写 `Log\s*in`（未登录站首页必有 `/login` 链接 → 几乎所有站被误判「踢回登录页」）②**请求失败 ≠ 两态不同**（sha256 空，`a==b` 失效 → 假成功）③别用 `bytes<200` 判空壳（滤掉 103B 真页），用 `base.looks_like_content()`

## 十二、测试基建铁律

1. **会写真实配置文件的测试先备份再还原**（曾删掉真实 auth.json）
2. **环境隔离**：`PENTEST_AUTH`/`PENTEST_SESSIONS` + `tempfile.mkdtemp()`
3. **靶场红时先分辨「数据脏」还是「代码错」**（P3 首跑 6 红 4 条数据不合格；P4 首跑 6 红 2 条 cookie 名写错）。**别改断言迁就**
4. **靶场必须自检 `status=None`**：忘 `verify_tls=False` 会让 HTTPS 全失败但表现为「站点没内容」→ **假通过**（P2/P4 各踩一次）
5. **规则数量别硬编码**，从 `rules.load_rules()` 动态取

## 十三、环境

- git：`C:/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`；`.gitignore` 排除 tools/、.sessions/、_lab/、凭据文件
- `git ls-files` 非 ASCII 转八进制 → `-z` + escape_decode；中文名 ENOSYS → `--ignore-errors`
- 沙箱 bash 缺 grep/tail/ls，用 python；`dangerouslyDisableSandbox` 后 HTTPS 出网可用
- Windows nmap 无 Npcap 时 `-sV` 挂起 → 降级 `-sT`
- **图表导出**：`show_widget` 用 CSS 变量，脱离宿主不显示。出附件单独写 SVG 写死颜色（浅色 #F1EFE8 底/#D3D1C7 边/#2C2C2A 字，危险 #FCEBEB/#A32D2D），转 PNG 用 Edge headless；校验尺寸 `struct.unpack('>II', d[16:24])`
- **bash 里别用反引号写中文块**（被当命令替换吃掉，曾损坏 MEMORY.md）。长文本用 Write 写文件

## 十四、PentAGI 评估结论（勿重复评估）

`D:\gihub\pentagi-main`（MIT，Go+Docker 12 服务）。**只借鉴方法论，不集成架构** —— Go/Python 不兼容、过度工程、其「Never request permission」与人工确认制对撞、全攻击链自动化对 SRC 是合规风险。已借鉴：置信度三级 / 覆盖度 / 脱敏 / CLI 反幻觉协议。

## 十五、项目台账

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效 7.4/7.7）、F-05(6.5)。
  2026-09-22 用 R012 对 8 个 in_scope 资产试跑：未命中未授权访问，但 `demo.ikuai8.com`
  和 `icc.ikuai8.com` 的 SPA bundle 匿名可下载，分别提取出 `/fs/*`、`/admin/index/*`
  和 `/console/*` 接口/路由清单；匿名请求被 catch-all 兜回首页/404，需登录态才能
  验证其鉴权。
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效 6.8/6.4）。2026-09-22 全资产重跑
  （11 资产 × 10 规则，覆盖 100/A）：11 条 detected 无高危，最高仍为 qmt COR-T01 6.8。
  **匿名侧确实扎实**；登录态（R010/R011）因无 Cookie 未覆盖 —— 唯一可能翻高危的方向。
  **⚠️ 其 SPA bundle 全在认证墙后**（登录页是纯静态「无权限页面」0 个 script，
  404 也 302 回 login）→ 匿名侧连前端代码都拿不到，「从 bundle 捞 API 清单」对该站无效，
  勿重复尝试。要挖访问控制只能靠登录 Cookie（**2 小时过期**，
  `laravel_session` + `XSRF-TOKEN` 缺一不可，三个子站不通用）
- 提交：fd24fc2 03f97bf 06f16d8 d9b908e e2afe00 ec6d98e 1b0f4e2 4d42efa 5ddf1ee 326682d
