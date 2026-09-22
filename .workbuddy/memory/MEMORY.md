# 项目记忆 - 自动挖洞平台

## 一、平台骨架

- `pentest-orchestrator/`：`orchestrator.py`(CLI) / `rules_engine.py` / `rules/` / `scanners.py`(nmap+nuclei) / `cvss.py` / `exploit.py`(人工确认制) / `manual_probe.py` / `coverage.py` / `evidence_lint.py` / `credentials.py`
- 子命令：`init plan autorun engage verify report status check lint submit coverage`
- 合规闸：授权确认 + 范围校验 + `auth.json`(4 项校验) + append-only 审计 + 破坏性阶段禁用 + `allow_scanner=false` 硬开关
- 置信度三级：`detected 🔍`→`confirmed ✅`→`exploited 💥`。**`detected` 不得提交 SRC**
- **回放**：`rate_findings` 重算会重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS：`compute_cvss31(av,ac,pr,ui,s,c,i,a)` / `compute_cvss40(av,ac,at,pr,ui,vc,vi,va,sc,si,sa)`。**4.0 的 UI 只有 N/A/P，3.1 `UI:R` 对应 `UI:P`**，传 R 抛异常。一律用引擎算
- 工具：nmap 7.92 / nuclei v3.11.1 / ffuf / gobuster / feroxbuster / subfinder / amass / httpx / sqlmap / wafw00f。缺 nikto/whatweb/hydra/john

### 通用工程坑
- **nuclei 必须 `-no-interactsh`**：约 710 模板回连 oast.*，被网关 SIGTERM 掐断（零输出无提示）
- **去重两层**：解析层 `(template_id,matched_at)` + 评级层 `(类别,归一化位置)`；`type=generic` 视为未知类别
- **「工具没装」先怀疑调用侧**：中文 Windows `encoding="utf-8"` 丢输出；`split()` 用在端口列表会让 nmap 把端口串当主机名卡满超时。**耗时恰为超时整数倍 = 参数拼错；秒返空 = 编码问题**
- Go 版本号先剥 ANSI 色码；`python -m <pkg>` 不万能；`_find_exe` 要认 `.bat/.cmd/.py`

## 二、补天公益 SRC 规则（用户纠正）

- **不需核备案、不需事先报备**。官方"报备"条款只针对专属SRC/众测
- **无资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致；ICP 只在提交时作第 2 项「归属证明」
- 红线：禁自动化扫描器、禁高并发、禁破坏性、禁用户数据、禁范围外、禁未授权横向
- 自律：单线程、间隔 ≥6s、单次 ≤10 请求，全部写审计链
- **提交模板 6 项**：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务。②③⑤ 需人工补
- 教训：**平台规则类建议先查官方文档，别靠行业通例推断**

## 三、手工只读核查手法（命中率从高到低）

`manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`
纪律写死在代码：仅 GET / 间隔 ≥6s / 单轮 ≤6 请求 / 证据 JSON + 审计链。

1. **⭐ 版本 → 厂商官方公告受影响范围（§四）**
2. **抓首页 href 的 host** 找业务系统 —— 比 crt.sh 更有效
3. **客户端安全控制绕过**：见"正在验证您是否是真人"就读 JS。若只是 `document.cookie=` + reload、服务端不校验 → 一条 curl 头绕过（CWE-602）
4. **后台入口常不在前台防护范围内**：`admin.php` 单独查
5. **弱口令可行性判据**：搜 `seccode/验证码/captcha`。有验证码就别碰
6. **软 404 用 sha256 比对**：200 但与首页同 hash = catch-all
7. **明文 HTTP 分资产测**：有 HSTS ≠ 80 端口跳 HTTPS
8. **归属证明取首页页脚**：ICP/主体/地址/版权一次拿全
9. **版本排除法**：先查修复版本，别硬套 CVE

### jiaoyu.cn 实战补充
- **安全头「占位符污染」**：头存在但值是 `value`/`off` → 浏览器忽略，防护失效。**比"缺失"更值得报**
- **定级必须三合一**：HSTS 失效 + 明文可达 + Cookie 缺 Secure = 6.8；单独报响应头只有 3.1
- **零破坏探测写鉴权**：`DELETE /api/xxx/999999999`。返回"未登录"=安全；返回"成功"/404=鉴权缺失
- **SPA 兜底假阳性**：`/.env` 200 但 hash 与首页一致 = catch-all
- **SPA 站归属取证**：去 `app.<hash>.js` 搜「版权所有/京ICP/有限公司」，一次拿全主体
- **「无测试账号」= 教育/政务类 SRC 硬阻塞**，必须提前说明预期。严禁为拿账号注册真实手机号、严禁测短信频控

## 四、⭐「版本命中官方公告」打法

**困境**：SRC 不许爆破，"无限爆破风险"怎么证明？
**解法**：拆成两条可只读取证的事实 —— ①版本落在厂商官方公告的受影响区间 ②站点未部署官方认可的缓解措施。两条成立即 confirmed，**不需要真爆破**。

实例 F-10（7.4/7.7）：`bbs.ikuai8.com` 页脚+meta 双处取证 `Discuz! X3.3` → 官方公告【2021】第 1 号**明文点名「X3.3 全部 Release」**，官方定级高，**已 EOL 无补丁** → 站点侧实测后台无验证码/人机验证可绕过/明文可达。

要点：查 CVE 更要查**厂商官方公告**（国内 CMS 以公告为准）；版本清单要逐条比对确认**被点名**；记下修复版本与 EOL 声明。公开研究可作"风险升级说明"，**标注未验证**。
定级：CWE-307 + CWE-1104，`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

## 五、只读规则引擎（核心能力）

`rules/` + `rules_engine.py` + `check`。靶场 `_test_rules_lab.py` 25/25。

- **不是扫描器**：不发 payload/不遍历/不并发/只 GET/HEAD → **不受 allow_scanner 闸约束**，但强制范围校验 + 限速 ≥6s + 请求预算 + 审计链
- **置信度恒为 detected**，绝不自动 confirmed；**排除必产 negative**（证明核查过）；预算耗尽标 `unfinished`
- R001 安全头占位符 / R002 客户端绕过 / R003 明文+Cookie / R004 后台入口 / R005 版本命中公告 / R006 catch-all 基线(抑制器) / R007 零破坏写探测(默认关) / R008 敏感文件 / R009 框架指纹 / **R010 凭据有效性(测试基建)** / **R011 双态鉴权差异**
- **关联分析比单条重要**：COR-T01(R001∧R003)=6.8；COR-A01(R004∧R005)=7.4。用 `supersedes` 避免重复提交
- 实战自动复现人工发现：bbs.ikuai8 → F-10(7.4)/F-05(6.5)；qmt.jiaoyu → J-01(6.8)

### 实现要点（复用时避开）
- **缓存 key 必须含请求头**：只按 (method,url) 会吞掉 R002「同 URL 带伪造 Cookie」的第二次请求（漏报不报错）。也因此登录态/匿名态天然隔离
- **`OpenerDirector.open()` 不接受 `context=`**：关 TLS 校验要 `build_opener(HTTPSHandler(context=ctx))`
- **`Powered by <a>X 3.3</a>` 正则里 `<...>` 必须整体可选** `(?:<[^>]*)?`
- **首页可能是拦截页**：版本在「绕过后的页面」→ 复用 R002 缓存（0 额外请求）
- **根路径跳 HTTPS ≠ 后台也跳**：R003 需对后台入口二段复检
- **靶场用协议嗅探单端口同时服务 HTTP/HTTPS**（首字节 0x16 = TLS ClientHello）

## 六、完整链路（P0）

`check → verify --rule → report → submit`（此前 check 是断头路，report 只读被闸禁的扫描器 findings）

- `session["rule_checks"][host]` = check 结果；`session["rule_verifications"][rule_id]` = 人工复核升级（report/submit 回放）
- `submit` 按补天 6 项模板出稿，**默认只输出 confirmed**
- `check --import-file` 零请求导入既有证据；report/verify/submit 均支持 `--session`

### 措辞铁律（会直接印进报告和提交稿）
- **规则名/发现名不写主观词**：「不跳转」→ 改；「返回完整内容」→ 实测字节数 `{bytes}B`。**能被机器验证的写事实，不能验证的别写形容词**
- 提交稿「影响分析」由 CVSS 向量推出「利用前提」(AV/AC/PR/UI/S) +「安全影响」(C/I/A)，不写套话

## 七、证据完整性铁律（两次翻车换来）

### 7.1 「缺失」与「值为 None」必须字面可区分
`cookie_flags` 用 `None` 表缺失 → 下游把 JSON `null` 读成「SameSite=None」，据此写出「Chrome 80+ 会拒绝该 Cookie」——**自我削弱附注**，等于替厂商备好驳回理由。
修复：缺失写字面量 `<未声明>` + `*_present` 布尔 + 单测锁死。
**通则：任何"属性不存在"的中间表示，都不能复用"属性有值"的值域。**

### 7.2 改了底层函数 ≠ 修好调用点
`fetch()` 加了 `follow_redirect`，但 `main()` 里仍 `fetch(u)` 默认跟随 → CLI 证据依旧错。
**凡修取证类 bug，必须端到端复跑并比对原始输出。**

### 7.3 urllib 默认跟随 30x
会把「明文 301」记成「200 不跳转」，曾使 3 条发现依据写错。判断跳转必须 `HTTPRedirectHandler.redirect_request` 返回 None，再从 `HTTPError.headers` 取 Location。

### 7.4 写前自问：这句措辞在帮我还是在帮厂商？
所有**降低本条危害性**的附注都要确认是否基于被误读的数据。真实减分项**必须如实写**；误读出的**必须删**。

## 八、证据自检 lint（P1）

`evidence_lint.py` + `orchestrator lint`。靶场 37/37。

**存在理由**：两次翻车的共同结构是**取证层取值正确、表述层结论错误**，单测抓不到（它测函数返回值，不测「结论与证据是否自洽」）。

17 条断言，离线不发请求。最巧的三条：
- **EL004**：证据 sha256 与请求流水里**另一 URL** 相同 → 跟随跳转拿到落地页的特征（无需知道是否跟随）
- **EL009**：自我削弱措辞（§7.4 的机器化），**引述语境豁免**
- **EL002**：`*_present=False` 却在文本里写成「属性=某值」

接入五处（缺一处门禁就是虚的）：`run_check` 出口 / `check --strict` / `lint --file|--session` / `report` 小节 / **`submit` 门禁**（阻断项默认不出稿，`--force` 才出且稿内留痕）。

### lint 自身的坑
- **结论文本与修复建议必须分开检查**：`remediation` 里的「应设为 SameSite=None」是建议值，计入会被当成「声称现状」→ 误报
- **合规闸统一 rc=2 + stderr**：`sys.exit("字符串")` 是 rc=1

## 九、框架指纹知识库（P2）

`rules/data/stacks.json`（14 栈）+ `R009`。靶场 `_test_stack_lab.py` 20/20。

**要解决的问题**：R001~R008 全是通用配置检查，命中率有天花板 —— 缺「这站是什么栈、该栈高发什么」。

### 三条硬边界（复用时别拆）
1. **指纹识别 0 额外请求** —— 复用 R006 首页基线 + R002 绕过后的页面缓存
2. **定向探针默认不跑** —— 仅 `--deep` 时于预算内执行，每栈 ≤4，全 GET 非触发
3. **`_never_probe` 永不自动请求** —— ThinkPHP invokefunction / SpringBoot `/actuator/heapdump` / Jenkins `/script`。测试直接断言「heapdump 从未出现在请求流水」

### 刻意不做
**不写 CVE 编号**：只给官方公告入口 + 风险类型，命中后 `needs_manual_check=True`。臆造 CVE 明令禁止。

### 实现要点
- 可靠度 high/medium/low，**low 不单独采信**
- **同栈多命中取可靠度最高，不是取第一条** —— 曾 `break` 取第一条，把 qmt 的 `XSRF-TOKEN`(medium) 当首选而漏掉 `laravel_session`(high)
- 探针结果必过 catch-all 比对；证据只留命中片段 + sha256，**绝不落正文**

### 实战
bbs.ikuai8 → Discuz!(body,high)；qmt.jiaoyu → Laravel(cookie,medium)。
⚠️ **Discuz 只在带 R002 绕过时才命中**（首页是拦截页）。三次印证：**编排顺序本身就是检测能力的一部分**。

## 十、覆盖度量化（P3）

`coverage.py` + `orchestrator coverage`。靶场 `_test_coverage.py` 62/62。

### 核心设计：必须拆成两个数
- `score` 核查完成度：相对「当前方法学可达范围」→ 多跑目标就涨
- `ceiling` 方法学上限：匿名+只读+conservative = **20%** → 改不了（结构性）

**刻意不把 ceiling 计入 score**：若计入，匿名只读永远不及格 → 分数失去区分度 → 没人看。结构性限制单列：不掩盖，也不污染可改进项。

五维度权重：资产 0.30 / 规则 0.25 / 完整性 0.15 / 栈定向 0.15 / 证据质量 0.15（复用 lint）。`绝对覆盖度 = score × ceiling / 100`。

### 分母可信性（错一个数字就是假报告）
- 资产分母取授权清单 `in_scope`，`out_of_scope` **不混入**
- 规则分母 = 全量 − 需 `--allow-write-probe` 且本轮未开启的
- 无任何证据时证据维度 = 0（否则空会话白拿 15%）
- 有资产 `unfinished` → 完整性 50% 且产 blocker gap

### 副产品：改进收益排序
`gain = (1 - score) × weight × 100` 降序输出。量化不只是给分数，而是让「下一步先做什么」可计算。
实测教训：直觉以为「1/3 资产」比「1/8 规则」缺口大，实际规则收益 21.9 > 资产 20.0 —— **边际收益必须算，不能猜**。

## 十一、登录态建模（P4）

`credentials.py` + R010/R011 + stacks.json 的 auth_paths。靶场 `_test_authz_lab.py` 44 条。

**存在理由**：匿名态下 coverage 的 auth 因子是 0.5，所有需登录的功能点/越权/业务逻辑不可见。有测试账号则 ceiling 翻倍（20% → 40%）。

### 凭据值零落盘（最硬的边界）
证据 JSON / 审计链 / 会话文件 / 报告里**只有 fingerprint 与 cookie 名**。
`Identity.as_dict()` 是唯一落盘出口，结构上不含值。请求流水记 `anon|<指纹>`。
凭据文件已进 .gitignore。**不提供「用账号密码自动登录」** —— 必触验证码/短信接口（触发即发真实短信），且易滑向口令爆破，两条都是红线。

### R010 为什么必须先于 R011
凭据无效时，R011 的双态对比会得出**假的阴性结论**（两态一致 → 判无差异 → 漏报），而不是如实说「没法判断」。所以必须先证明 Cookie 真的生效。
两种判据：①响应差异 ②**Set-Cookie 差异**（更硬，不可省）。
②不可省的理由：很多站首页对匿名和登录返回同一份内容，只靠①会把这类站全判 inconclusive，而它们恰恰可能藏着最严重的鉴权缺失。**不能因为怀疑自己的凭据就漏报。**

### R011 三重假阳性抑制
catch-all 兜底 / 登录页错误页 / **首页 `/` 排除**（公开首页两态一致是正常设计，不排除就是每站一条假阳性）。
凭据 invalid/inconclusive 时**拒绝下结论**：「两态一致只说明未测出差异，不等于鉴权缺失」。

### 三个真 bug（复用时避开）
1. **登录页正则别写 `Log\s*in`** —— 未登录站点首页必然有 `/login` 链接，连写的 "login" 会被匹配成登录页 → 几乎所有站点被误判「已被踢回登录页」。只认 password 输入框、明确中文短语、带空格的 Sign in / Log in
2. **请求失败 ≠ 两态不同** —— TLS/连接失败时 sha256 为空，`a==b` 判据失效，会凭空造出「凭据生效」的假成功结论。必须有 failed 判定
3. **别用字节数阈值判空壳** —— `bytes<200` 把 103B 的真实页面也滤掉了。用 `base.looks_like_content()`（64B + 非错误页/登录页）

## 十二、测试基建铁律

1. **会写真实配置文件的测试，先备份再还原**（`_test_authgate.py` 曾删掉真实 auth.json）
2. **合规闸统一 rc=2 + 显式写 stderr**
3. **Windows 不能用 SO_REUSEADDR 探测端口**（允许重复绑定）
4. **测试必须环境隔离**：`PENTEST_AUTH` / `PENTEST_SESSIONS` + `tempfile.mkdtemp()`
5. **靶场红时先分辨「被测数据脏」还是「代码错」** —— P3 首跑 6 红，4 条是我构造的数据不合格；P4 首跑 6 红，2 条是靶场 cookie 名写错。**别急着改断言迁就**
6. **靶场必须自检 `status=None`**：忘了 `verify_tls=False` 会让 HTTPS 全失败，但表现是「站点没内容」而非「请求失败」，测试**假通过**。这个坑 P2 踩过、P4 又踩
7. **规则数量别硬编码在测试里**：新增规则后不该是 coverage 的错，从 `rules.load_rules()` 动态取

## 十三、环境

- git 不在 PATH：`C:/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`；`.gitignore` 排除 tools/、.sessions/、_lab/、凭据文件
- `git ls-files` 非 ASCII 转八进制 → 用 `-z` + escape_decode；中文名 ENOSYS → `--ignore-errors`
- 沙箱 bash 缺 grep/tail/ls，用 python 替代；`dangerouslyDisableSandbox` 后 HTTPS 出网可用
- Windows nmap 无 Npcap 时 `-sV` 挂起 → 降级 `-sT`
- **图表导出**：`show_widget` 用 CSS 变量，脱离宿主不显示。出附件要单独写 SVG 写死颜色（浅色 #F1EFE8 底/#D3D1C7 边/#2C2C2A 字，危险 #FCEBEB/#A32D2D），转 PNG 用 Edge headless；校验尺寸用 `struct.unpack('>II', d[16:24])`（PIL 未装）
- **bash 里别用反引号写中文块**：会被当命令替换吃掉（曾损坏 MEMORY.md）。长文本用 Write 写文件再追加

## 十四、PentAGI 评估结论（勿重复评估）

`D:\gihub\pentagi-main`（MIT，Go+Docker 12 服务）。**只借鉴方法论，不集成架构** —— Go/Python 不兼容、过度工程、其「Never request permission」与人工确认制对撞、全攻击链自动化对 SRC 是合规风险。
已借鉴落地：置信度三级 / 覆盖度评估 / 脱敏规范 / CLI 反幻觉协议。

## 十五、已完成项目（勿重复开挖）

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效，7.4/7.7）
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效，6.8/6.4）。**该站鉴权扎实，未挖到高危**；登录态因无账号未覆盖 —— P4 落地后，若有测试账号可直接重跑 R010/R011
