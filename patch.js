#!/usr/bin/env node
/**
 * CloakBrowser Pro · one-shot license-gate patch
 * ----------------------------------------------
 *
 *   node ./patch.js "D:\packages\chromium-155.0.8059.39.1-pro"
 *   node ./patch.js "…\chrome.exe" --dry-run
 *   node ./patch.js "…\chrome.dll" --revert
 *
 * What it does, in order:
 *   1. finds chrome.dll from a folder / chrome.exe / chrome.dll path
 *   2. locates the lease-signature gate in the license runtime:
 *        lea  r9, [rip + <32-byte server public key>]
 *        call ED25519_verify          <-- this 5-byte slot
 *        cmp  eax, 1 / sete
 *      The 32-byte key sits exactly 0x20 bytes before the
 *      "/api/license/session/end" string, so the slot is found by following
 *      every `lea r9, [rip+key]` — no version table required, and it works on
 *      builds that are already patched (`B8 01 00 00 00` instead of `E8 …`).
 *   3. rewrites each slot to `B8 01 00 00 00` (`mov eax,1`), so the boolean
 *      check always takes the "signature valid" path
 *   4. writes a one-time `chrome.dll.orig` backup, verifies every byte it wrote
 *
 * No dependencies, no network, no launch: this only edits the DLL on disk.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

const PATCH_BYTES = Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
const CALL_OPCODE = 0xe8;
const PATCHED_OPCODE = 0xb8;

const START_PATH = '/api/license/session/start';
const END_PATH = '/api/license/session/end';
const PUBKEY_BACKOFF = 0x20; // key occupies the 32 bytes right before END_PATH
const SLOT_SCAN_BYTES = 48; // how far past `lea r9,[rip+key]` the slot can sit

/** Builds whose site table is known up front (sha256 of the *unpatched* DLL). */
const PROFILES = [
    {
        version: '154.0.8037.57.1',
        sha256: '8a9f1e9020bac1f4c19b5bd8b7fba8e6f8432d2c4755bf5539afbecb1ec9f18f',
        verifyVa: 0x1888c3010,
        sites: [0x18938c10a, 0x18938d656, 0x18938e143, 0x18938ed00],
    },
    {
        version: '155.0.8059.39.1',
        sha256: '336f3af913c2a3cdbc6679ada4550ff04b80e27ade54a6c8d8fbb64c9877ff74',
        verifyVa: 0x188b3eb50,
        sites: [0x18960dfba, 0x18960f520, 0x18961000d, 0x189610c20],
    },
    {
        // chromium-156.0.8078.47.7-pro (Windows x64). Note: the `mov r8,r13`
        // before one gate ends in an `e8` ModRM byte, so the old "first e8"
        // heuristic false-positives one byte early; the sites below are the
        // real `call verify` instructions and discovery now groups by target.
        version: '156.0.8078.47.7',
        sha256: '1d34c68df07a423b0c431f18330ce89fb7c4d51daec05b475168be6e0f2b0252',
        verifyVa: 0x188cdb510,
        sites: [0x1897ac181, 0x1897ada94, 0x1897ae66f, 0x1897af2d4],
    },
];

const HELP = `CloakBrowser Pro · one-shot license-gate patch

usage:
  node index.js <browser path> [options]
  node index.js <path> <path> …            patch several builds in one run

  <browser path>   build folder, chrome.exe, chromium.exe or chrome.dll

options:
  -n, --dry-run        show what would happen, write nothing
      --revert         restore chrome.dll from chrome.dll.orig
      --no-backup      do not create chrome.dll.orig
      --sites LIST     override slots, e.g. 0x18960dfba,0x18960f520
      --verify-va VA   override the verify routine address, e.g. 0x188b3eb50
      --json           machine-readable report
  -h, --help           this text

exit codes: 0 = ok / nothing to do, 1 = failure, 2 = usage
`;

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const dim = text => (color ? `\u001b[2m${text}\u001b[0m` : text);
const bold = text => (color ? `\u001b[1m${text}\u001b[0m` : text);
const red = text => (color ? `\u001b[31m${text}\u001b[0m` : text);
const green = text => (color ? `\u001b[32m${text}\u001b[0m` : text);
const yellow = text => (color ? `\u001b[33m${text}\u001b[0m` : text);

const hex = value => `0x${value.toString(16)}`;
const hex5 = buf => [...buf].map(byte => byte.toString(16).padStart(2, '0')).join(' ');

// ---------------------------------------------------------------------------
// PE32+ reading
// ---------------------------------------------------------------------------

function readAt(fd, offset, length) {
    const buf = Buffer.alloc(length);
    const read = fs.readSync(fd, buf, 0, length, offset);
    return buf.subarray(0, read);
}

function sha256File(file) {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(file, 'r');
    try {
        const buf = Buffer.allocUnsafe(1 << 22);
        for (let pos = 0; ;) {
            const read = fs.readSync(fd, buf, 0, buf.length, pos);
            if (!read) break;
            hash.update(buf.subarray(0, read));
            pos += read;
        }
    } finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}

function parsePe(fd) {
    const head = readAt(fd, 0, 0x1000);
    if (head[0] !== 0x4d || head[1] !== 0x5a) throw new Error('not a PE file (missing MZ)');
    const eLfanew = head.readUInt32LE(0x3c);
    if (readAt(fd, eLfanew, 4).toString('latin1') !== 'PE\0\0') {
        throw new Error('not a PE file (missing PE signature)');
    }
    const coff = eLfanew + 4;
    const sectionCount = head.readUInt16LE(coff + 2);
    const sizeOfOptional = head.readUInt16LE(coff + 16);
    const opt = coff + 20;
    const magic = head.readUInt16LE(opt);
    if (magic !== 0x20b) throw new Error(`expected PE32+ (x64), got magic 0x${magic.toString(16)}`);

    const imageBase = Number(head.readBigUInt64LE(opt + 24));
    const sections = [];
    for (let i = 0; i < sectionCount; i++) {
        const at = opt + sizeOfOptional + i * 40;
        sections.push({
            name: head.toString('latin1', at, at + 8).replace(/\0+$/, ''),
            va: head.readUInt32LE(at + 12),
            rawSize: head.readUInt32LE(at + 16),
            rawPtr: head.readUInt32LE(at + 20),
        });
    }
    return { imageBase, sections };
}

const sectionByName = (pe, name) => pe.sections.find(entry => entry.name === name);

function vaToOffset(pe, va) {
    const rva = va - pe.imageBase;
    for (const entry of pe.sections) {
        if (rva >= entry.va && rva < entry.va + entry.rawSize) return entry.rawPtr + (rva - entry.va);
    }
    return null;
}

function offsetToVa(pe, offset) {
    for (const entry of pe.sections) {
        if (offset >= entry.rawPtr && offset < entry.rawPtr + entry.rawSize) {
            return pe.imageBase + entry.va + (offset - entry.rawPtr);
        }
    }
    return null;
}

function findStringVa(fd, pe, sectionName, needle) {
    const sec = sectionByName(pe, sectionName);
    if (!sec) return null;
    const needleBuf = Buffer.from(needle, 'latin1');
    const end = sec.rawPtr + sec.rawSize;
    const step = 8 << 20;
    for (let pos = sec.rawPtr; pos < end; pos += step) {
        const chunk = readAt(fd, pos, Math.min(step + needle.length, end - pos));
        const at = chunk.indexOf(needleBuf);
        if (at >= 0) return offsetToVa(pe, pos + at);
    }
    return null;
}

/** File offsets of `lea reg, [rip+disp]` pointing at `targetVa`. */
function findRipRefsTo(fd, pe, targetVa) {
    const sec = sectionByName(pe, '.text');
    if (!sec) return [];
    const prefixes = [];
    for (const rex of [0x48, 0x4c]) {
        for (const modrm of [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d]) {
            prefixes.push(Buffer.from([rex, 0x8d, modrm]));
        }
    }
    const step = 8 << 20;
    const overlap = 16;
    const chunk = Buffer.allocUnsafe(Math.min(step + overlap, sec.rawSize));
    const found = new Set();
    const end = sec.rawPtr + sec.rawSize;
    for (let pos = sec.rawPtr; pos < end; pos += step) {
        const read = fs.readSync(fd, chunk, 0, Math.min(chunk.length, end - pos), pos);
        if (!read) break;
        for (const prefix of prefixes) {
            let i = chunk.indexOf(prefix);
            while (i >= 0 && i + 7 <= read) {
                const insnVa = pe.imageBase + sec.va + (pos - sec.rawPtr) + i;
                if (insnVa + 7 + chunk.readInt32LE(i + 3) === targetVa) found.add(pos + i);
                i = chunk.indexOf(prefix, i + 1);
            }
        }
    }
    return [...found].sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// detection
// ---------------------------------------------------------------------------

/** VA of the embedded 32-byte server public key, or null for a free build. */
function findPubkeyVa(fd, pe) {
    const endVa = findStringVa(fd, pe, '.rdata', END_PATH);
    if (endVa == null) return null;
    const pubVa = endVa - PUBKEY_BACKOFF;
    const offset = vaToOffset(pe, pubVa);
    if (offset == null) return null;
    const blob = readAt(fd, offset, 32);
    if (blob.length !== 32 || blob.every(byte => byte === 0)) return null;
    return pubVa;
}

/**
 * Everything right after one `lea r9, [rip+pubkey]` that could be a gate slot:
 *   - every `call rel32` whose target lands inside .text (the untouched gate), and
 *   - a `mov eax,1` slot (`B8 01 00 00 00`) left by a previous bypass.
 *
 * Scanning for the *first* `e8` is too naive: the instruction right before the
 * real call can end in an `e8` ModRM byte (e.g. `4d 89 e8` = `mov r8, r13`),
 * so a byte-scan finds a "call" one byte early whose target jumps out of range.
 * Collecting only in-range calls and grouping by target fixes that.
 */
function candidatesAfterLea(fd, leaOffset, leaVa, textLo, textHi) {
    const window = readAt(fd, leaOffset + 7, SLOT_SCAN_BYTES);
    const calls = [];
    const patched = [];
    for (let i = 0; i + 5 <= window.length; i++) {
        if (window[i] === PATCHED_OPCODE && window.readInt32LE(i + 1) === 1) {
            patched.push(leaVa + 7 + i);
        } else if (window[i] === CALL_OPCODE) {
            const va = leaVa + 7 + i;
            const target = va + 5 + window.readInt32LE(i + 1);
            if (target >= textLo && target < textHi) calls.push({ va, target });
        }
    }
    return { calls, patched };
}

/**
 * Version- and state-independent: anchor on the key blob, follow every
 * `lea r9, [rip+pubkey]`, and keep the call target they all share — that shared
 * target is the Ed25519 verify routine and its call sites are the gate slots.
 * A lone target (only one ref ever points at it) is not trusted, so a stray
 * in-range `call` cannot masquerade as the gate routine. Works on an untouched
 * build (`E8` slots) and on an already-bypassed one (`mov eax,1`).
 */
function discoverSites(fd, pe) {
    const pubVa = findPubkeyVa(fd, pe);
    if (pubVa == null) return null;
    const text = sectionByName(pe, '.text');
    if (!text) return null;
    const textLo = pe.imageBase + text.va;
    const textHi = textLo + text.rawSize;

    const callSites = [];
    const patchedSites = [];
    for (const refOffset of findRipRefsTo(fd, pe, pubVa)) {
        if (refOffset < text.rawPtr || refOffset >= text.rawPtr + text.rawSize) continue;
        const leaVa = pe.imageBase + text.va + (refOffset - text.rawPtr);
        const { calls, patched } = candidatesAfterLea(fd, refOffset, leaVa, textLo, textHi);
        callSites.push(...calls);
        patchedSites.push(...patched);
    }

    const byTarget = new Map();
    for (const call of callSites) {
        if (!byTarget.has(call.target)) byTarget.set(call.target, []);
        byTarget.get(call.target).push(call.va);
    }
    let verifyVa = null;
    let gateSites = [];
    if (byTarget.size) {
        const [bestTarget, bestSites] = [...byTarget.entries()].sort((a, b) => b[1].length - a[1].length)[0];
        if (bestSites.length >= 2) {
            verifyVa = bestTarget;
            gateSites = bestSites;
        }
    }
    gateSites = gateSites.concat(patchedSites);

    const seen = new Set();
    const unique = gateSites.filter(va => (seen.has(va) ? false : (seen.add(va), true))).sort((a, b) => a - b);
    if (!unique.length) return null;

    return {
        verifyVa,
        sites: unique,
        source: `pubkey ${hex(pubVa)} (${patchedSites.length}/${unique.length} patched)`,
        discovered: true,
    };
}

/** Every profiled slot is either patched or a call to the profiled routine. */
function profileFits(fd, pe, profile) {
    for (const va of profile.sites) {
        const offset = vaToOffset(pe, va);
        if (offset == null) return false;
        const cur = readAt(fd, offset, 5);
        if (cur.equals(PATCH_BYTES)) continue;
        if (cur[0] !== CALL_OPCODE) return false;
        if (va + 5 + cur.readInt32LE(1) !== profile.verifyVa) return false;
    }
    return true;
}

/** hash match → structural match → public-key discovery. */
function choosePlan(fd, pe, hash, options) {
    if (options.sites) {
        return {
            verifyVa: options.verifyVa ?? null,
            sites: options.sites,
            source: 'command line override',
        };
    }
    const byHash = PROFILES.find(profile => profile.sha256 === hash);
    if (byHash) return { ...byHash, source: `known build ${byHash.version} (sha256)` };

    const byStructure = PROFILES.find(profile => profileFits(fd, pe, profile));
    if (byStructure) return { ...byStructure, source: `known build ${byStructure.version} (structural)` };

    return discoverSites(fd, pe);
}

// ---------------------------------------------------------------------------
// patch / revert
// ---------------------------------------------------------------------------

function inspect(dll, options = {}) {
    const stat = fs.statSync(dll);
    const hash = sha256File(dll);
    const fd = fs.openSync(dll, 'r');
    let pe;
    try {
        pe = parsePe(fd);
        const plan = choosePlan(fd, pe, hash, options);
        const hasRuntime = findStringVa(fd, pe, '.rdata', START_PATH) != null;

        if (!plan) {
            return {
                dll, hash, size: stat.size, pe, plan: null,
                noLicenseRuntime: !hasRuntime, sites: [], conflicts: [],
                patched: false,
                backupExists: fs.existsSync(`${dll}.orig`),
            };
        }

        const sites = plan.sites.map(va => {
            const fileOffset = vaToOffset(pe, va);
            if (fileOffset == null) throw new Error(`slot ${hex(va)} is not backed by file data`);
            const cur = readAt(fd, fileOffset, 5);
            const isCall = cur[0] === CALL_OPCODE;
            return {
                va,
                fileOffset,
                bytes: cur,
                patched: cur.equals(PATCH_BYTES),
                isCall,
                targetVa: isCall ? va + 5 + cur.readInt32LE(1) : null,
            };
        });
        const conflicts = sites.filter(site =>
            !site.patched && !(site.isCall && (plan.verifyVa == null || site.targetVa === plan.verifyVa)));

        return {
            dll, hash, size: stat.size, pe, plan, sites, conflicts,
            noLicenseRuntime: !hasRuntime,
            patched: sites.length > 0 && sites.every(site => site.patched),
            backupExists: fs.existsSync(`${dll}.orig`),
        };
    } finally {
        fs.closeSync(fd);
    }
}

function patch(dll, options) {
    const report = inspect(dll, options);
    if (report.noLicenseRuntime) {
        return { ...report, skipped: 'this build has no license runtime (free build) — nothing to bypass' };
    }
    if (!report.plan) {
        throw new Error(
            'could not locate the signature gate in this build. '
            + 'Pass --sites 0x…,0x… (and --verify-va 0x…) after inspecting it manually',
        );
    }
    if (report.conflicts.length) {
        throw new Error(
            `unexpected bytes at ${report.conflicts.map(site => `${hex(site.va)}=${hex5(site.bytes)}`).join(', ')} `
            + '— refusing to touch them. Pass --sites to override if you are sure',
        );
    }

    const todo = report.sites.filter(site => !site.patched);
    const result = { ...report, todo, written: 0, backupPath: null, backupCreated: false };
    if (options.dryRun) return result;

    if (todo.length && options.backup) {
        const backupPath = `${dll}.orig`;
        if (!fs.existsSync(backupPath)) {
            fs.copyFileSync(dll, backupPath);
            result.backupCreated = true;
        }
        result.backupPath = backupPath;
    }
    if (!todo.length) return result;

    const fd = fs.openSync(dll, 'r+');
    try {
        for (const site of todo) {
            fs.writeSync(fd, PATCH_BYTES, 0, 5, site.fileOffset);
            if (!readAt(fd, site.fileOffset, 5).equals(PATCH_BYTES)) {
                throw new Error(`write verification failed at ${hex(site.va)}`);
            }
            result.written++;
        }
    } finally {
        fs.closeSync(fd);
    }
    result.hashAfter = sha256File(dll);
    return result;
}

function revert(dll) {
    const backupPath = `${dll}.orig`;
    if (!fs.existsSync(backupPath)) throw new Error(`no backup at ${backupPath}`);
    fs.copyFileSync(backupPath, dll);
    return { dll, restoredFrom: backupPath, hash: sha256File(dll) };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
    const options = { paths: [], dryRun: false, revert: false, backup: true, json: false, help: false };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        switch (arg) {
            case '-n': case '--dry-run': options.dryRun = true; break;
            case '--revert': options.revert = true; break;
            case '--no-backup': options.backup = false; break;
            case '--json': options.json = true; break;
            case '-h': case '--help': options.help = true; break;
            case '--sites': {
                const value = argv[++i];
                if (!value) throw new Error('--sites needs a value like 0x18960dfba,0x18960f520');
                options.sites = value.split(/[,\s]+/).filter(Boolean).map(text => Number(text));
                break;
            }
            case '--verify-va': {
                const value = argv[++i];
                if (!value) throw new Error('--verify-va needs a value like 0x188b3eb50');
                options.verifyVa = Number(value);
                break;
            }
            default:
                if (arg.startsWith('-')) throw new Error(`unknown option ${arg}`);
                options.paths.push(arg);
        }
    }
    return options;
}

/** Folder / chrome.exe / chrome.dll -> the chrome.dll to patch. */
function resolveDll(input) {
    const target = path.resolve(input);
    if (!fs.existsSync(target)) throw new Error(`path does not exist: ${target}`);
    const stat = fs.statSync(target);

    if (stat.isDirectory()) {
        for (const name of ['chrome.exe', 'chromium.exe']) {
            const exe = path.join(target, name);
            if (!fs.existsSync(exe)) continue;
            const dll = path.join(target, 'chrome.dll');
            if (!fs.existsSync(dll)) {
                throw new Error(`browser folder incomplete: chrome.dll missing next to ${exe}`);
            }
            return dll;
        }
        const dll = path.join(target, 'chrome.dll');
        if (fs.existsSync(dll)) return dll;
        throw new Error(`no chrome.exe / chrome.dll inside ${target}`);
    }

    const name = path.basename(target).toLowerCase();
    if (name === 'chrome.dll') return target;
    if (name === 'chrome.exe' || name === 'chromium.exe') {
        const dll = path.join(path.dirname(target), 'chrome.dll');
        if (!fs.existsSync(dll)) {
            throw new Error(`browser folder incomplete: chrome.dll missing next to ${target}`);
        }
        return dll;
    }
    throw new Error('expected a build folder, chrome.exe, chromium.exe or chrome.dll');
}

function printReport(dll, before, result, options) {
    const lines = [];
    lines.push(bold('CloakBrowser Pro · license gate patch'));
    lines.push(`  target   : ${dll}`);
    lines.push(`  file     : ${before.size.toLocaleString('en-US')} bytes`);
    lines.push(`  sha256   : ${before.hash}`);

    if (before.noLicenseRuntime) {
        lines.push(`  build    : free build (no license runtime)`);
        lines.push(`  action   : ${yellow('nothing to patch')}`);
        return lines.join('\n');
    }

    const buildLine = before.plan
        ? `${before.plan.source}${before.plan.verifyVa != null ? `  verify=${hex(before.plan.verifyVa)}` : ''}`
        : 'unknown';
    lines.push(`  build    : ${buildLine}`);
    lines.push(`  slots    : ${before.sites.length}`);
    for (const site of before.sites) {
        lines.push(`             ${hex(site.va)}  ${hex5(site.bytes)}  ${site.patched ? green('patched') : (site.isCall ? 'call' : yellow('unexpected'))}`);
    }
    if (before.conflicts.length) {
        lines.push(`  ${red(`conflicts: ${before.conflicts.map(site => hex(site.va)).join(', ')}`)}`);
    }

    if (options.dryRun) {
        lines.push(`  action   : ${yellow(`dry run — ${result.todo.length} slot(s) would be rewritten`)}`);
        return lines.join('\n');
    }
    if (!result.todo.length) {
        lines.push(`  action   : ${green('nothing to do — already patched')}`);
        return lines.join('\n');
    }

    lines.push(`  backup   : ${result.backupPath ?? '(disabled)'}${result.backupCreated ? '  (created)' : ''}`);
    lines.push(`  patched  : ${result.written} slot(s)  →  b8 01 00 00 00  (mov eax, 1)`);
    lines.push(`  sha256   : ${before.hash}  →  ${result.hashAfter}`);
    lines.push(`  verify   : all ${before.sites.length} slot(s) read back as patched`);

    const after = inspect(dll);
    const ok = after.patched && after.conflicts.length === 0;
    lines.push(`  result   : ${ok ? green('OK — license signature gate bypassed') : red('FAILED re-check')}`);
    if (ok) {
        lines.push('');
        lines.push(dim('  next: run this build through cloak-pro-nopatch (read-only) or'));
        lines.push(dim('        cloak-pro-unlimited (also patches) with any non-empty licenseKey.'));
    }
    return lines.join('\n');
}

function toJson(dll, before, result, options) {
    return JSON.stringify({
        dll,
        action: options.revert ? 'revert' : options.dryRun ? 'dry-run' : 'patch',
        size: before?.size ?? null,
        sha256Before: before?.hash ?? null,
        sha256After: options.dryRun ? null : (result?.hashAfter ?? result?.hash ?? null),
        build: before?.plan ? { source: before.plan.source, verifyVa: before.plan.verifyVa } : null,
        noLicenseRuntime: Boolean(before?.noLicenseRuntime),
        sites: (before?.sites ?? []).map(site => ({
            va: hex(site.va),
            bytes: hex5(site.bytes),
            patched: site.patched,
        })),
        conflicts: (before?.conflicts ?? []).map(site => hex(site.va)),
        written: result?.written ?? 0,
        backup: result?.backupPath ?? null,
        backupCreated: Boolean(result?.backupCreated),
        skipped: result?.skipped ?? null,
    }, null, 2);
}

function main() {
    let options;
    try {
        options = parseArgs(process.argv.slice(2));
    } catch (error) {
        console.error(red(String(error.message)));
        console.error(dim('see --help'));
        return 2;
    }
    if (options.help || (!options.paths.length && process.argv.length <= 2)) {
        console.log(HELP);
        return options.help ? 0 : 2;
    }
    if (!options.paths.length) {
        console.error(red('no browser path given'));
        return 2;
    }

    let exitCode = 0;
    const jsonOut = [];

    for (const input of options.paths) {
        let dll;
        try {
            dll = resolveDll(input);
        } catch (error) {
            console.error(red(`✕ ${input}: ${error.message}`));
            exitCode = 1;
            continue;
        }

        try {
            if (options.revert) {
                const result = revert(dll);
                if (options.json) jsonOut.push({ dll, action: 'revert', sha256: result.hash, restoredFrom: result.restoredFrom });
                else console.log(`${bold('CloakBrowser Pro · revert')}\n  target   : ${dll}\n  restored : ${result.restoredFrom}\n  sha256   : ${result.hash}\n  result   : ${green('OK')}`);
                continue;
            }

            const before = inspect(dll, options);
            const result = patch(dll, options);

            if (options.json) jsonOut.push(JSON.parse(toJson(dll, before, result, options)));
            else console.log(printReport(dll, before, result, options) + '\n');

            if (result.conflicts?.length) exitCode = 1;
        } catch (error) {
            exitCode = 1;
            if (options.json) jsonOut.push({ dll, error: error.message });
            else console.error(`${red('✕')} ${dll}\n  ${error.message}\n`);
        }
    }

    if (options.json) console.log(JSON.stringify(jsonOut.length === 1 ? jsonOut[0] : jsonOut, null, 2));
    return exitCode;
}

process.exitCode = main();
