#!/usr/bin/env node
/**
 * tools/find-gate.mjs — 定位 CloakBrowser Pro 的 license 签名校验门（只读）
 *
 * 用法:
 *   node tools/find-gate.mjs <chrome.dll>
 *
 * 输出: DLL 的 sha256、内嵌 Ed25519 公钥、共享的 verify 例程地址、每个签名门
 *       槽位的调用点及当前状态（E8=未补 / B8 01 00 00 00=已补），并打印一段可
 *       直接粘贴进 patch.js PROFILES / inspect.ts KNOWN_PROFILES 的档案对象。
 *
 * 原理（见 docs/UPGRADING-CLOAKBROWSER.md）:
 *   公钥 32 字节固定在 "/api/license/session/end" 字符串前 0x20 字节；每个门是
 *   `lea r9,[rip+公钥]` 后紧跟一条 `call ED25519_verify`。多处门调用同一个 verify
 *   例程，所以按 call 目标分组、取被多个 lea 共同指向的目标，能避免把前一条指令
 *   的 `e8`（如 `4d 89 e8`=mov r8,r13 的 ModRM 字节）误判成 call。
 *
 * 只读，不写盘。零依赖，Node ≥18。
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const CALL = 0xe8;
const PATCH_BYTES = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax,1
const END_PATH = '/api/license/session/end';
const START_PATH = '/api/license/session/start';
const PUBKEY_BACKOFF = 0x20; // 公钥占 END_PATH 前 32 字节
const SCAN = 48;             // lea 之后扫描多少字节找 call / 补丁槽

const hex = n => `0x${n.toString(16)}`;

function readAt(fd, off, len) {
    const b = Buffer.alloc(len);
    const n = fs.readSync(fd, b, 0, len, off);
    return b.subarray(0, n);
}
function sha256File(f) {
    const h = crypto.createHash('sha256');
    const fd = fs.openSync(f, 'r');
    try {
        const b = Buffer.allocUnsafe(1 << 22);
        for (let p = 0; ;) { const n = fs.readSync(fd, b, 0, b.length, p); if (!n) break; h.update(b.subarray(0, n)); p += n; }
    } finally { fs.closeSync(fd); }
    return h.digest('hex');
}
function parsePe(fd) {
    const head = readAt(fd, 0, 0x1000);
    if (head[0] !== 0x4d || head[1] !== 0x5a) throw new Error('不是 PE 文件（缺 MZ）');
    const e = head.readUInt32LE(0x3c);
    if (readAt(fd, e, 4).toString('latin1') !== 'PE\0\0') throw new Error('不是 PE 文件（缺 PE 签名）');
    const coff = e + 4, nsec = head.readUInt16LE(coff + 2), szopt = head.readUInt16LE(coff + 16), opt = coff + 20;
    const magic = head.readUInt16LE(opt);
    if (magic !== 0x20b) throw new Error(`需要 PE32+ (x64)，实际 magic=0x${magic.toString(16)}`);
    const imageBase = Number(head.readBigUInt64LE(opt + 24));
    const sections = [];
    for (let i = 0; i < nsec; i++) {
        const at = opt + szopt + i * 40;
        sections.push({
            name: head.toString('latin1', at, at + 8).replace(/\0+$/, ''),
            va: head.readUInt32LE(at + 12),
            rawSize: head.readUInt32LE(at + 16),
            rawPtr: head.readUInt32LE(at + 20),
        });
    }
    return { imageBase, sections };
}
const secOf = (pe, n) => pe.sections.find(s => s.name === n);
function vaToOff(pe, va) { const r = va - pe.imageBase; for (const s of pe.sections) if (r >= s.va && r < s.va + s.rawSize) return s.rawPtr + (r - s.va); return null; }
function offToVa(pe, off) { for (const s of pe.sections) if (off >= s.rawPtr && off < s.rawPtr + s.rawSize) return pe.imageBase + s.va + (off - s.rawPtr); return null; }
function findStringVa(fd, pe, sec, needle) {
    const s = secOf(pe, sec); if (!s) return null;
    const nb = Buffer.from(needle, 'latin1'); const step = 8 << 20;
    for (let p = s.rawPtr; p < s.rawPtr + s.rawSize; p += step) {
        const ch = readAt(fd, p, Math.min(step + nb.length, s.rawPtr + s.rawSize - p));
        const at = ch.indexOf(nb); if (at >= 0) return offToVa(pe, p + at);
    }
    return null;
}
/** 所有目标为 targetVa 的 `lea reg,[rip+disp32]`（REX.W/R × reg 0..7）所在文件偏移。 */
function findLeaRefs(fd, pe, targetVa) {
    const s = secOf(pe, '.text'); if (!s) return [];
    const prefixes = [];
    for (const rex of [0x48, 0x4c]) for (let reg = 0; reg < 8; reg++) prefixes.push(Buffer.from([rex, 0x8d, 0x05 | (reg << 3)]));
    const step = 8 << 20, overlap = 16, found = new Set();
    for (let p = s.rawPtr; p < s.rawPtr + s.rawSize; p += step) {
        const ch = readAt(fd, p, Math.min(step + overlap, s.rawPtr + s.rawSize - p));
        for (const pre of prefixes) {
            let i = ch.indexOf(pre);
            while (i >= 0 && i + 7 <= ch.length) {
                const insnVa = pe.imageBase + s.va + (p - s.rawPtr) + i;
                if (insnVa + 7 + ch.readInt32LE(i + 3) === targetVa) found.add(p + i);
                i = ch.indexOf(pre, i + 1);
            }
        }
    }
    return [...found].sort((a, b) => a - b);
}

function main() {
    const dll = process.argv[2];
    if (!dll) { console.error('用法: node tools/find-gate.mjs <chrome.dll>'); process.exit(2); }
    if (!fs.existsSync(dll)) { console.error('文件不存在: ' + dll); process.exit(1); }

    const hash = sha256File(dll);
    const size = fs.statSync(dll).size;
    const fd = fs.openSync(dll, 'r');
    try {
        const pe = parsePe(fd);
        const startVa = findStringVa(fd, pe, '.rdata', START_PATH);
        const endVa = findStringVa(fd, pe, '.rdata', END_PATH);
        console.log('dll        :', dll);
        console.log('size       :', size.toLocaleString('en-US'), 'bytes');
        console.log('sha256     :', hash, '  (未打补丁原版哈希，写进档案)');
        if (startVa == null || endVa == null) {
            console.log('license    : 无 license runtime（free build）—— 无需破解');
            return;
        }
        const pubVa = endVa - PUBKEY_BACKOFF;
        const blob = readAt(fd, vaToOff(pe, pubVa), 32);
        console.log('license    : 有 license runtime');
        console.log('pubkey VA  :', hex(pubVa));
        console.log('pubkey hex :', blob.toString('hex'));

        const text = secOf(pe, '.text');
        const textLo = pe.imageBase + text.va, textHi = textLo + text.rawSize;
        const calls = []; const patched = [];
        for (const refOff of findLeaRefs(fd, pe, pubVa)) {
            if (refOff < text.rawPtr || refOff >= text.rawPtr + text.rawSize) continue;
            const leaVa = pe.imageBase + text.va + (refOff - text.rawPtr);
            const win = readAt(fd, refOff + 7, SCAN);
            for (let i = 0; i + 5 <= win.length; i++) {
                if (win[i] === CALL) {
                    const va = leaVa + 7 + i;
                    const tgt = va + 5 + win.readInt32LE(i + 1);
                    if (tgt >= textLo && tgt < textHi) calls.push({ va, tgt });
                } else if (win[i] === 0xb8 && win.readInt32LE(i + 1) === 1) {
                    patched.push(leaVa + 7 + i);
                }
            }
        }
        const byTgt = new Map();
        for (const c of calls) { (byTgt.get(c.tgt) ?? byTgt.set(c.tgt, []).get(c.tgt)).push(c.va); }
        let verifyVa = null, sites = [];
        if (byTgt.size) {
            const [t, arr] = [...byTgt.entries()].sort((a, b) => b[1].length - a[1].length)[0];
            if (arr.length >= 2) { verifyVa = t; sites = arr; }
        }
        sites = [...new Set([...sites, ...patched])].sort((a, b) => a - b);
        if (!sites.length) { console.log('\n未定位到签名门：布局可能不是 4 处 lea+call，请人工用 --sites/--verify-va 处理。'); return; }

        console.log('candidates :', calls.length + patched.length, '(落在 .text 内的 call 候选 + 已补槽位)');
        console.log('verifyVa   :', verifyVa == null ? '(全部已补，无法从 call 读出)' : hex(verifyVa));
        console.log('sites      :', sites.length);
        for (const va of sites) {
            const off = vaToOff(pe, va); const cur = readAt(fd, off, 5);
            const state = cur.equals(PATCH_BYTES) ? 'patched(B8 01 00 00 00)'
                : cur[0] === CALL ? `call->${hex(va + 5 + cur.readInt32LE(1))}` : `? ${cur.toString('hex')}`;
            console.log(`             ${hex(va)}  ${cur.toString('hex')}  ${state}`);
        }
        console.log('\n--- 粘贴进 patch.js 的 PROFILES 与 src/inspect.ts 的 KNOWN_PROFILES ---');
        console.log(`{`);
        console.log(`    version: '<在 chrome.exe/文件版本里填，如 156.0.8078.47.7>',`);
        console.log(`    sha256: '${hash}',`);
        console.log(`    verifyVa: ${verifyVa == null ? '0x0' : hex(verifyVa)},`);
        console.log(`    sites: [${sites.map(hex).join(', ')}],`);
        console.log(`},`);
    } finally { fs.closeSync(fd); }
}
main();
