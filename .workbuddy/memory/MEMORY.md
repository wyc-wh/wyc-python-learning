# 项目记忆 - 自动挖洞平台

## 一、平台与编排器

- `pentest-orchestrator/`：orchestrator.py(CLI) / scanners.py(nmap+nuclei 只读) / cvss.py(3.1+4.0 双标准) / exploit.py(人工确认制) / webui.py / manual_probe.py(手工核查)
- 子命令：init / plan / autorun(仅只读) / engage / verify / report / status
- 合规闸：授权确认 + 范围校验 + `auth.json` 授权清单(4 项校验) + append-only JSONL 审计 + 破坏性阶段默认禁用 + `allow_scanner=false` 硬开关
- 置信度三级：`detected 🔍`(扫描器命中) → `confirmed ✅`(人工复核) → `exploited 💥`。**`detected` 不得提交 SRC**
- **回放机制（关键坑）**：`rate_findings` 会重算并重置置信度 → `generate_report` 必须回放 `session["verifications"]`
- CVSS：`compute_cvss31(av,ac,pr,ui,s,c,i,a)` 8 参 / `compute_cvss40(av,ac,at,pr,ui,vc,vi,va,sc,si,sa)` 11 参（4.0 的 UI 用 `N/A/P`，无 `R`）。**一律用引擎算，别手算**
- 工具：nmap 7.92 + nuclei v3.11.1 + 模板 13742 个在 `tools/`；另装 ffuf/gobuster/feroxbuster/subfinder/amass/httpx/sqlmap/wafw00f。缺 nikto/whatweb/hydra/john（需 Perl/Ruby/gcc）
- **报告必须含「覆盖度与结论边界」章节**，声明「未扫到 ≠ 不存在」

### 已踩过的坑（别再犯）
- **nuclei 默认必须 `-no-interactsh`**：约 710 个模板回连 oast.*，被网关判恶意流量直接 SIGTERM 掐断整条扫描（零输出无提示）
- **结果去重两层**：解析层 `(template_id, matched_at)` + 评级层 `(类别, 归一化位置)`。nuclei 单模板可对同一 URL 吐 11 条
- **`lines.append(*list)` 是错的** → `lines.extend(list)`
- **「工具没装」先怀疑调用侧**：① 中文 Windows 下 `encoding="utf-8"` 丢输出 → 多编码回退 ② `split()` 用在端口列表上会让 nmap 把端口串当主机名卡满超时。**判别指纹：耗时恰为超时整数倍 = 参数拼错；秒返空 = 编码问题**。别轻易归因沙箱
- Go 系版本号先剥 ANSI 色码；`python -m <pkg>` 不万能（wafw00f 无 `__main__.py`）；`_find_exe` 要认 `.bat/.cmd/.py`
- nuclei 的 `type=generic` 视为未知类别，允许与内置类别同位置折叠，否则去重失效
- **⚠️ urllib 默认跟随 30x，会把『明文 HTTP 301 跳转』记成『200 不跳转』** ——
  曾因此把 3 条发现（ikuai8 F-01/F-06/F-11）的依据写成错的，差点带错证据提交。
  凡判断跳转行为，必须 `HTTPRedirectHandler.redirect_request` 返回 None 禁跟随，
  再从 `HTTPError.headers` 取 Location。`manual_probe.py` 已加 `follow_redirect` 参数

## 二、补天公益 SRC 规则（用户 2026-09-21 纠正，务必遵守）

- **公益SRC 不需要核备案，也不需要事先报备**。官方"报备"条款只针对「核心功能篡改、批量数据操作」等影响业务连续性/用户数据安全的测试，且该条约束的是**专属SRC/众测**。公益SRC =「随机发现→提交→平台审核→企业认领」，无事前审批入口
- **公益SRC 没有资产白名单**。范围判据 = 官网首页公开链出 + 版权/主体一致
- ICP 备案只在**提交时**用作官方模板第 2 项「归属证明」
- 红线：禁自动化扫描器、禁高并发、禁破坏性、禁用户数据、禁范围外、禁未授权横向
- 目标侧自律：单线程、间隔 ≥6s、单次任务 ≤10 请求，全部写审计链
- **官方提交模板 6 项**（butian.net/Article/content/id/543）：①URL ②归属证明 ③首页截图含地址栏 ④漏洞证明 ⑤爱站权重 ⑥活动任务。②③⑤ 需人工浏览器补；收录细则看 `butian.net/Help/plan`
- 教训：**涉及平台规则的流程性建议，先搜官方文档，别靠行业通例推断**（曾把专属SRC的"白名单"套到公益SRC上，给了错误指引）

## 三、手工只读核查套路（可复用，命中率从高到低）

`python manual_probe.py --host <h> --session <id> --paths /,/robots.txt --check-http`
纪律写死在代码里：仅 GET / 间隔 ≥6s / 单轮 ≤6 请求 / 证据 JSON + 审计链。

1. **⭐ 版本 → 厂商官方公告受影响范围（最高价值，见 §四）**
2. **抓首页 href 的 host** 找业务系统 —— 比 crt.sh 更有效（crt.sh 226 条完全漏掉 6 个官网链出子域）
3. **客户端安全控制绕过**：见"正在验证您是否是真人"就去读 JS。若只是 `document.cookie=...` + reload、服务端不校验 → 一条 curl 头绕过（CWE-602）
4. **后台入口往往不在前台防护范围内**：`admin.php` 常不受人机验证保护，需单独查
5. **弱口令可行性判据**：页面搜 `seccode`/`验证码`/`captcha`/`AliyunCaptcha.js`。全 0 + 人机验证可绕过 = 具备爆破条件；有验证码就别碰
6. **软 404 用 sha256 比对**：`/administrator/` 返回 200 但与首页同 hash = catch-all，状态码会骗人
7. **明文 HTTP 分资产测**，管理入口单独看：有 HSTS ≠ 明文不返回内容，还得看 80 端口是否跳转
8. **归属证明取首页页脚**：ICP号/主体全称/地址/版权 一次拿全，正对模板第 2 项
9. **版本排除法**：拿到版本先查修复版本。AList v3.63.0 > 3.57.0 → 排除 CVE-2026-25161，别硬套 CVE

## 四、⭐「版本命中官方公告」打法（2026-09-22 首次跑通，解决了合规困境）

**困境**：SRC 不允许爆破/利用，那"无限爆破风险"这类漏洞怎么证明？

**解法**：把成立要件拆成两条可只读取证的事实：
1. **版本落在厂商官方安全公告公布的受影响区间**
2. **站点未部署任一官方认可的缓解措施**

两条都成立即 confirmed，**不需要真的爆破成功**。执行爆破既无必要也违规。

**实例（F-10 高危 7.4/7.7）**：
- `bbs.ikuai8.com` 页脚 + meta generator 双处取证 `Discuz! X3.3`
- Discuz! 官方公告【2021】第 1 号受影响清单**明文列出「Discuz! X3.3 全部已发布的 Release 版本」**，官方定级**高**，危害「无法正确统计登录失败次数 → 无限次爆破 → 非法控制账号」，且 X3.3 **已 EOL 无补丁**
- 站点侧实测：后台无验证码 / 前台人机验证可绕过 / `admin.php` 不受验证保护 / 明文 HTTP 可达

**要点**：
- 查的不只是 CVE，**更要查厂商官方安全公告**（CVE 常滞后或缺失；Discuz 这类国内 CMS 以公告为准）
- 公告里的「受影响版本清单」要逐条比对，确认目标版本被**点名**
- 顺带记下官方**修复版本**和 **EOL 声明**（EOL = 只能升级，补丁建议失效）
- 公开研究（如 360CERT 的 authkey 缺陷 + 后台 UCenter 写入 RCE）可作为"风险升级说明"写进影响分析，**标注未验证**

**定级参考**：CWE-307（无认证尝试限制）+ CWE-1104（未维护组件），
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → 3.1 **7.4** / 4.0 **7.7**

## 五、测试基建铁律

1. **会写真实配置文件的测试，必须先备份再还原**（`_test_authgate.py` 曾删掉真实 auth.json）
2. **合规闸统一 rc=2 + 显式写 stderr**（`sys.exit("字符串")` 是 rc=1，测试会漏判）
3. **Windows 不能用 SO_REUSEADDR 探测端口** —— 允许重复绑定，探测永远成功
4. **测试必须环境隔离**：`PENTEST_AUTH` / `PENTEST_SESSIONS` 环境变量 + `tempfile.mkdtemp()`，不碰真实文件

## 六、环境

- git 不在 PATH：`C:/Users/wd/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd/git.exe`；仓库已建，`.gitignore` 排除 tools/、.sessions/、_lab/
- `git ls-files` 把非 ASCII 转义成八进制 → 用 `-z` + escape_decode；个别中文名报 ENOSYS → `--ignore-errors`
- 沙箱 bash 缺 grep/tail/ls/dirname，用 python 替代；`dangerouslyDisableSandbox` 后 HTTPS 出网可用
- Windows nmap 无 Npcap 时 `-sV` 挂起 → 降级 `-sT`
- **图表导出**：`show_widget` 用 CSS 变量，脱离宿主不显示。出附件要单独写 SVG 并写死颜色（浅色 #F1EFE8 底/#D3D1C7 边/#2C2C2A 字，危险项 #FCEBEB/#A32D2D），转 PNG 用 Edge headless：
  `msedge.exe --headless=new --disable-gpu --no-sandbox --hide-scrollbars --force-device-scale-factor=2 --window-size=680,368 --screenshot=out.png in.svg`
  校验尺寸用 `struct.unpack('>II', d[16:24])`（PIL 未装）

## 七、PentAGI 评估结论（勿重复评估）

`D:\gihub\pentagi-main`（MIT，Go+Docker 12 服务）。**只借鉴方法论，不集成架构** ——
Go vs Python 不兼容、过度工程、其提示词明令「Never request permission」与人工确认制哲学对撞、全攻击链自动化对 SRC 是合规风险。
已借鉴落地：置信度三级模型 / 覆盖度评估 / 脱敏规范 / CLI 反幻觉协议。

## 新增可复用手法（2026-09-22 jiaoyu.cn 实战）

- **安全头「占位符污染」**：响应头存在但值是字面量 `value`/`off`/模板变量 → 浏览器忽略，
  防护失效。**比"缺失"更值得报**（运维误以为已防护）。取证前先排除自己脚本脱敏的可能。
  定级必须三合一：HSTS失效 + 明文HTTP可达不跳转 + 会话Cookie缺Secure = 6.8；
  单独报"响应头问题"只有 3.1 分，会被判影响不大。
- **零破坏探测写操作鉴权**：`DELETE /api/xxx/999999999`（不存在的ID）。
  返回"未登录"= 鉴权在路由前（安全）；返回"成功"/404 = 鉴权缺失（高危）。删的也是不存在的资源。
- **SPA 兜底假阳性**：`/.env` 返回 200 但体积/_hash 与某 SPA 首页一致 = catch-all，非泄露。
- **SPA 站归属取证**：页脚是 JS 渲染的，去 `app.<hash>.js` 搜「版权所有/京ICP/有限公司」，
  一次拿全主体+地址+备案号，比查备案库更硬（站点自身声明）。bundle 里还能捞 API 清单与子域。
- **「无测试账号」= 教育/政务类 SRC 硬阻塞**：未登录态天花板就是配置类问题。
  必须提前向用户说明预期，别挖完才说没高危。严禁为拿账号用真实手机号注册、
  严禁测短信接口频控（触发即发真实短信）。

## 已完成项目（勿重复开挖）

- **ikuai8.com**：F-10 高危（Discuz! X3.3 EOL + 登录失败计数失效，7.4/7.7）
- **jiaoyu.cn**：J-01 中危（qmt 安全头占位符失效，6.8/6.4）。**该站鉴权扎实，未挖到高危**，
  已登录态因无账号未覆盖 —— 若要深挖需先解决测试账号问题

## 只读规则引擎（2026-09-22 落地）

`rules/` + `rules_engine.py` + `orchestrator.py check` 子命令。靶场 `_test_rules_lab.py` 21 项断言。

- **不是扫描器**：不发 payload/不遍历/不并发/默认只 GET/HEAD → **不受 allow_scanner 闸约束**，
  但强制范围校验 + 单线程限速(≥6s) + 请求预算 + 审计链
- **置信度恒为 detected 🔍**，绝不自动 confirmed —— 规则命中 ≠ 已确认
- **排除必产 negative**（证明核查过），预算耗尽标 `unfinished`
- 8 条规则：R001 安全头占位符污染 / R002 客户端绕过 / R003 明文+Cookie / R004 后台入口 /
  R005 版本命中官方公告 / R006 catch-all 基线(抑制器) / R007 零破坏写探测(默认关) / R008 敏感文件
- 关联分析比单条规则重要：COR-T01(R001∧R003)=6.8 传输层链；COR-A01(R004∧R005)=沿用公告向量 7.4
- 实战已自动复现人工发现：bbs.ikuai8.com → F-10(7.4)/F-05(6.5)；qmt.jiaoyu.cn → J-01(6.8)
- `check --auth-manifest` 支持多项目授权清单隔离（auth.json 只能描述一个项目）

### 规则引擎实现要点（复用时避开）

- **缓存 key 必须含请求头**：只按 (method,url) 会吞掉 R002「同一 URL 带伪造 Cookie」的第二次请求（漏报，不报错）
- **`OpenerDirector.open()` 不接受 `context=`**：只有 `urlopen` 接受；关 TLS 校验要 `build_opener(HTTPSHandler(context=ctx))`
- **`Powered by <a>X 3.3</a>` 正则里 `<...>` 必须整体可选** `(?:<[^>]*)?`，否则纯文本页脚全漏
- **首页可能是拦截页**：版本等信息在「绕过后的页面」里 → R005 复用 R002 的缓存再取一次（0 额外请求）
- **根路径跳 HTTPS ≠ 后台也跳**：R003 需对后台入口做二段复检
- **靶场用协议嗅探单端口同时服务 HTTP/HTTPS**（首字节 0x16 = TLS ClientHello）
