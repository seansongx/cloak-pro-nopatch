# CloakBrowser 更新后的修复 & 发布手册（Runbook）

> 目标：CloakBrowser Pro 每次出新版本后，按本手册重新定位 license 签名门、更新档案、验证、发布到 npm。
> 本文以 **156.0.8078.47.7（Windows x64）** 这次升级为范例，命令可直接套用到下一个版本。

---

## 0. 一页速查（下次只照这个做）

```bash
# 0) 临时放 Pro key（只在 shell 里，绝不写进代码/仓库）
export CLOAKBROWSER_LICENSE_KEY=cb_xxxxxxxx        # PowerShell: $env:CLOAKBROWSER_LICENSE_KEY="cb_xxx"

# 1) 查最新版
curl -s https://cloakbrowser.dev/api/download/version -H "X-Platform: windows-x64"
#   -> {"version":"156.0.8078.47.7"}

# 2) 下载该版本 zip（必须带 key）
curl -L -o cb.zip "https://cloakbrowser.dev/api/download/<VERSION>" \
     -H "X-Platform: windows-x64" -H "Authorization: Bearer $CLOAKBROWSER_LICENSE_KEY"
#   校验：sha256 必须等于 release 页 SHA256SUMS-<VERSION> 里 cloakbrowser-windows-x64.zip 那行

# 3) 解出 chrome.dll，用工具定位签名门
node tools/find-gate.mjs chrome.dll
#   输出 verifyVa 和 sites，以及可直接粘贴的档案对象

# 4) 把档案补进两处：
#    - patch.js                        的 PROFILES
#    - src/inspect.ts                  的 KNOWN_PROFILES
#   （sha256 用“未打补丁原版”的哈希）

# 5) 验证
node ./patch.js "<浏览器目录>" --dry-run     # 命中 known build，4 槽位，0 冲突
node ./patch.js "<浏览器目录>"               # OK — license signature gate bypassed
node ./patch.js "<浏览器目录>" --revert      # 能还原原版
npm run typecheck && npm run build
#   并发启动冒烟（见第 6 节）

# 6) 发布（升版本 → commit → push → 打 tag → GitHub Actions 自动发 npm）
```

---

## 1. 原理（为什么能破）

CloakBrowser Pro 的 license runtime 用 **Ed25519** 校验服务端下发的租约（lease token）。汇编形态：

```
lea  r9, [rip + <32字节服务端公钥>]   ; 第 4 个参数 = 公钥
...  xor ecx,ecx / xor edx,edx / mov r8,<msg> / mov rcx,<sig>
call ED25519_verify                  ; 校验签名
cmp  eax, 1 / sete ...               ; 结果决定放行/拒绝
```

- **公钥位置固定**：32 字节公钥正好在 `.rdata` 里 `"/api/license/session/end"` 字符串**前 0x20 字节**。
- **签名门（gate）**：一串 `lea r9,[rip+公钥]` + `call ED25519_verify`，通常 **4 处**，都调用**同一个** verify 例程。
- **破解**：把每处 `call`（`E8 rel32`，5 字节）改成 `B8 01 00 00 00`（`mov eax,1`），让校验恒真。
- **多开**：本项目的运行时模块（`src/`）另起一个**进程内本地授权 API**（`127.0.0.1` 随机端口），把浏览器的 license 请求重定向过去；本地 API 的 `active` 恒为 0，于是**不限席位**。DLL 打补丁（绕过签名）+ 本地 API（伪造租约）两件事缺一不可。

---

## 2. 本次升级记录（156）— 留档对照

| 项 | 值 |
|---|---|
| 版本（Win x64 / Linux） | `156.0.8078.47.7` / `156.0.8078.47.8` |
| 下载 zip | `cloakbrowser-windows-x64.zip`，541,904,682 字节 |
| zip sha256 | `6f8ac2665b34d9a4fd20fc2fcc608206e1f46f8f8ce2036005bad629ba8b0af9` |
| **chrome.dll 未打补丁 sha256** | `1d34c68df07a423b0c431f18330ce89fb7c4d51daec05b475168be6e0f2b0252` |
| 公钥 VA / hex | `0x19304df00` / `619750ac24a66fcf6854032758859e7984870a32e4dc0151bb78f4df06a4f6b5` |
| **verifyVa** | `0x188cdb510` |
| **sites（4 处）** | `0x1897ac181` `0x1897ada94` `0x1897ae66f` `0x1897af2d4` |

### 这次的坑（务必记住）

旧版发现逻辑「在 `lea r9,[rip+公钥]` 后 24 字节内找第一个 `e8`」在 156 上会**误判**：
某个门前面的 `mov r8,r13` 指令字节是 `4d 89 e8`，最后一个字节 `e8` 是 **ModRM**，不是 call；旧逻辑把它当成 call，目标越界 → `patch.js` 报
`unexpected bytes at 0x1897ae66e=e8 e8 9c ce 52`。

**修复**：改为「收集 lea 后所有**落在 .text 内**的 `call rel32`，按**目标分组**，取被多个 lea 共同指向（≥2）的目标作为 verify 例程，其调用点即 gate」。已固化进 `patch.js` / `src/inspect.ts` 的 `discoverSites`，并有独立工具 `tools/find-gate.mjs`。

---

## 3. 详细步骤

### 前置
- 一个有效的 CloakBrowser **Pro** key（能下载 Pro 二进制）。**只放 shell 环境变量，不写进任何文件/提交。**
- 已装 `cloakbrowser` + `playwright-core`（验证启动要用）：`npm i`（peer 会自动装）。

### Step 1 — 查最新稳定版
```bash
curl -s https://cloakbrowser.dev/api/download/version -H "X-Platform: windows-x64"
# 返回 {"version":"..."}，即当前 Windows x64 最新 Pro 版
# 或看 GitHub：https://api.github.com/repos/CloakHQ/CloakBrowser/releases
```
> 注意：不带 `X-Platform` 时接口返回的是 free 轨道的最新版（如 150.x），别混淆；一定带平台头。

### Step 2 — 下载并校验
```bash
curl -L -o cb.zip "https://cloakbrowser.dev/api/download/<VERSION>" \
     -H "X-Platform: windows-x64" -H "Authorization: Bearer $CLOAKBROWSER_LICENSE_KEY"
```
用 release 页 `SHA256SUMS-<VERSION>` 里 `cloakbrowser-windows-x64.zip` 那行核对 sha256。
> SourceForge 上只镜像 `SHA256SUMS`/源码/README，**二进制只能在带 key 的接口下**。

### Step 3 — 解出 DLL + 定位签名门
解压 zip 得到 `chrome.dll`，然后：
```bash
node tools/find-gate.mjs chrome.dll
```
输出示例（156）：
```
sha256     : 1d34c68df07a423b0c431f18330ce89fb7c4d51daec05b475168be6e0f2b0252 ...
pubkey VA  : 0x19304df00
verifyVa   : 0x188cdb510
sites      : 4  (0x1897ac181 0x1897ada94 0x1897ae66f 0x1897af2d4)
--- 粘贴进 patch.js / inspect.ts ---
{ version: '<...>', sha256: '1d34...', verifyVa: 0x188cdb510, sites: [...] },
```
若工具报「未定位到签名门」，说明布局变了（不是 N 处 `lea+call`），需人工用 `patch.js --sites … --verify-va …` 覆盖。

### Step 4 — 写档案（两处，缺一不可）
1. `patch.js` 的 `PROFILES` 数组追加一条：
   ```js
   {
       version: '156.0.8078.47.7',
       sha256: '1d34c68df07a423b0c431f18330ce89fb7c4d51daec05b475168be6e0f2b0252',
       verifyVa: 0x188cdb510,
       sites: [0x1897ac181, 0x1897ada94, 0x1897ae66f, 0x1897af2d4],
   },
   ```
2. `src/inspect.ts` 的 `KNOWN_PROFILES[<同一个 sha256>] = { version, verifyVa, sites }`。
- `sha256` 一定是**未打补丁原版**的哈希（打过补丁后哈希会变，靠结构匹配兜底）。

### Step 5 — 更新文档
`README.md` 的「内置 profile」版本表加一行（版本 / sha256 前 16 位 / verifyVa / 槽位数）。

---

## 4. 验证清单

```bash
# a) 命中档案、结构正确
node ./patch.js "<目录>" --dry-run --json
#    期望: build.source = "known build 156... (sha256)", 4 槽位, conflicts: []

# b) 真打补丁
node ./patch.js "<目录>"
#    期望: "OK — license signature gate bypassed"，4 槽位读回 b8 01 00 00 00

# c) 只读体检（模块侧）
node -e "import('./dist/src/inspect.js').then(m=>console.log(m.inspectBrowser('<目录>/chrome.dll')))"
#    期望: patched:true, conflicts:0

# d) 还原
node ./patch.js "<目录>" --revert   # 还原到原版 sha256

# e) 类型 + 构建
npm run typecheck && npm run build
```

### 并发启动冒烟（核心功能）

前提：指向**已打补丁**的构建目录。用真实 Pro key（本地授权 API 只对 key 做 sha256 一致性比对，任意合法格式 `cb_...` 均可）。

```js
// _smoke.mjs
import { launch, shutdown } from './dist/index.js';
const key = process.env.CB_KEY, dir = process.argv[2], N = 5;
const t0 = Date.now();
const rs = await Promise.all(Array.from({ length: N }, async (_, i) => {
  const b = await launch({ headless: true, licenseKey: key, browserDir: dir });
  try { const v = await b.version(); const p = await b.newPage();
        await p.goto('https://example.com', { timeout: 60000 });
        return `#${i+1} ${v} "${await p.title()}"`; }
  finally { await b.close().catch(()=>{}); }
}));
console.log(rs.join('\n')); console.log(`ok=${rs.length} in ${((Date.now()-t0)/1000).toFixed(1)}s`);
await shutdown();
```
```bash
CB_KEY=cb_xxx node _smoke.mjs "<已打补丁目录>"      # 期望 5 个都打印 "Example Domain"
```
> 多开数量受本机内存/CPU 限制（每个 headless chromium 数百 MB）；代码层面无席位上限。

---

## 5. 发布流程（GitHub → npm）

发布由 `.github/workflows/npm-publish.yml` 自动完成。触发：push `v*` tag / 发布 Release / 手动 dispatch。

```bash
# 1) 升版本号（例如 1.3.0 -> 1.3.1）
#    编辑 package.json "version"
git add -A && git commit -m "chore: release 1.3.1" && git push origin main
# 2) 打 tag 推送，自动触发发布
git tag v1.3.1 && git push origin v1.3.1
```
Action 会：`npm ci` → `npm run typecheck` → 校验 tag 名 == package.json 版本 → `npm publish --access public --provenance`（`prepublishOnly` 自动 `build`）。

**前置（只需配一次）**：仓库 Settings → Secrets and variables → Actions 加 secret **`NPM_TOKEN`**（npm 的 Automation/Publish token）。

**注意**
- 发布 registry 由 `publishConfig.registry=https://registry.npmjs.org/` 固定，避免本机 npmmirror 镜像干扰。
- `--provenance` 需要**公共仓库**。
- 刚发完在 npm 上查可能短暂 404 / 还是旧版本 —— 那是**元数据传播延迟**（约 15~30s），稍等重查即可，不是失败。
- `git push origin <tag>` 只触发发布；普通 `push main` 不会发布。

---

## 6. 排错

| 现象 | 原因 / 处理 |
|---|---|
| `could not locate the signature gate` | 布局不是预期 N 处 `lea+call`。用 `tools/find-gate.mjs` 看，或 `--sites`/`--verify-va` 手动指定 |
| `unexpected bytes at 0x…=e8 e8 …` | 旧「第一个 e8」启发式误命中（`mov r8,r13` 的 ModRM=e8）。用分组工具/新版 `discoverSites`，别退回去找第一个 e8 |
| 下载 401 | key 缺失/失效；确认 `Authorization: Bearer cb_...` |
| `npm whoami` → ENEEDAUTH / 发版失败 | 本机没登录 npm，或仓库没配 `NPM_TOKEN`；本机 registry 是 npmmirror 也不能发布 |
| npm 刚发完 404 | 传播延迟，等 15~30s 重查 `https://registry.npmjs.org/<pkg>?t=随机` |
| 并发启动个别失败 | 先看内存/CPU；不是破解问题 |

---

## 7. 关键常量 & 位置速查

| 名称 | 值/说明 |
|---|---|
| `END_PATH` | `/api/license/session/end` |
| `START_PATH` | `/api/license/session/start`（判断有没有 license runtime） |
| `PUBKEY_BACKOFF` | `0x20`（公钥在 END_PATH 前 32 字节） |
| 槽位补丁字节 | `B8 01 00 00 00`（mov eax,1） |
| 未补字节形态 | `E8 rel32`（call ED25519_verify） |
| 已补字节形态 | `B8 01 00 00 00` |
| 本地 API 环境变量 | `CLOAKBROWSER_LICENSE_API`（模块注入） |
| 锁定构建环境变量 | `CLOAKBROWSER_BINARY_PATH` / `executablePath` |

---

## 8. 相关文件

| 路径 | 作用 |
|---|---|
| `patch.js` | 一次性补丁 CLI（改 chrome.dll + `.orig` 备份 + `--revert`）；`PROFILES` 档案表 |
| `src/inspect.ts` | 只读检测：`KNOWN_PROFILES`、`discoverSites`（公钥锚定发现） |
| `tools/find-gate.mjs` | 定位签名门的小工具（只读，输出可粘贴档案） |
| `src/server.ts` | 进程内本地授权 API（多开核心） |
| `.github/workflows/npm-publish.yml` | 打 tag/发 Release 自动发布到 npm |
| `docs/UPGRADING-CLOAKBROWSER.md` | 本手册 |
