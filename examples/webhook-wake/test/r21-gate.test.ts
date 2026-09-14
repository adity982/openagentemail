/**
 * #177 hardening：marker symlink / timer 上限 / alert scheme /
 * .dirsync wake 前可移除性 / 非 loopback opt-in —— 正负控。
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MAX_ALERT_HOOK_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  MAX_SEND_TIMEOUT_MS,
  parseFileConfig,
  type FileConfig,
} from '../src/config.ts';
import { DedupError, DedupStore, inspectDedupFile } from '../src/dedup.ts';
import { canReplaceDedupTarget, inspectStateWritable } from '../src/readiness.ts';
import {
  FIXTURE_SECRET,
  mailBody,
  postHook,
  startReceiver,
  tempDir,
  testConfig,
  writeSecretFile,
} from './helpers.ts';
import type { Receiver } from '../src/server.ts';

const receivers: Receiver[] = [];
afterEach(async () => {
  while (receivers.length) await receivers.pop()!.close();
});

function fileBase(dir: string): FileConfig {
  const secret = writeSecretFile(dir, 'ok.whs', FIXTURE_SECRET);
  return {
    routes: {
      canary: {
        subscriptionId: 'whk_4a1b8c2d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
        domain: 'openagent.email',
        mailbox: 'alice@openagent.email',
        secretFile: secret,
        terminal: 'term_examplecanary0001',
      },
    },
  };
}

describe('R21 marker symlink-safe persistUnacked', () => {
  test('正控：常规 commit 仍持久化并清除 .unacked', async () => {
    const dir = tempDir();
    const path = join(dir, 'dedup.json');
    const store = new DedupStore({
      path,
      retentionMs: 7 * 24 * 60 * 60 * 1000,
      maxRecords: 8,
    });
    await store.commit(
      {
        key: 'whk_4a1b8c2d-5e6f-4a7b-8c9d-0e1f2a3b4c5d:evt_11111111-2222-3333-4444-555555555555',
        status: 'success',
        storedAtMs: 1,
        expiresAtMs: 9_999_999_999_999,
      },
      1,
    );
    expect(existsSync(path)).toBe(true);
    expect(existsSync(store.unackedPath())).toBe(false);
  });

  test('负控：.unacked 为指向敏感文件的 symlink 时必须拒绝写入', async () => {
    const dir = tempDir();
    const path = join(dir, 'dedup.json');
    const victim = join(dir, 'victim-secret.txt');
    writeFileSync(victim, 'KEEP_ME\n', { mode: 0o600 });

    // 预置 symlink：inspect/requireDurable 必须 fail-closed（不跟随）
    symlinkSync(victim, `${path}.unacked`);
    expect(inspectDedupFile(path)).toEqual({ ok: false, reason: 'state_unacked' });
    const early = new DedupStore({
      path,
      retentionMs: 7 * 24 * 60 * 60 * 1000,
      maxRecords: 8,
    });
    await expect(
      early.commit(
        {
          key: 'whk_4a1b8c2d-5e6f-4a7b-8c9d-0e1f2a3b4c5d:evt_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          status: 'success',
          storedAtMs: 2,
          expiresAtMs: 9_999_999_999_999,
        },
        2,
      ),
    ).rejects.toMatchObject({ message: 'dedup_unacked_not_file' });
    expect(readFileSync(victim, 'utf8')).toBe('KEEP_ME\n');

    // 在 persistUnacked 前瞬间植入 symlink，咬 O_NOFOLLOW（mutation 去掉后会写穿 victim）
    unlinkSync(`${path}.unacked`);
    const store = new DedupStore(
      { path, retentionMs: 7 * 24 * 60 * 60 * 1000, maxRecords: 8 },
      {
        onDirFsync: () => {
          if (!existsSync(store.unackedPath())) {
            symlinkSync(victim, store.unackedPath());
          }
        },
      },
    );
    await expect(
      store.commit(
        {
          key: 'whk_4a1b8c2d-5e6f-4a7b-8c9d-0e1f2a3b4c5d:evt_bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
          status: 'success',
          storedAtMs: 3,
          expiresAtMs: 9_999_999_999_999,
        },
        3,
      ),
    ).rejects.toMatchObject({ message: 'dedup_unacked_symlink' });
    expect(readFileSync(victim, 'utf8')).toBe('KEEP_ME\n');
  });
});

describe('R21 timer load-time caps', () => {
  test('正控：推荐区间内接受；负控：超上沿与 >2^31-1 拒载', () => {
    const dir = tempDir();
    const base = fileBase(dir);
    expect(parseFileConfig({ ...base, requestTimeoutMs: MAX_REQUEST_TIMEOUT_MS }).requestTimeoutMs).toBe(
      MAX_REQUEST_TIMEOUT_MS,
    );
    expect(parseFileConfig({ ...base, sendTimeoutMs: MAX_SEND_TIMEOUT_MS }).sendTimeoutMs).toBe(
      MAX_SEND_TIMEOUT_MS,
    );
    expect(
      parseFileConfig({ ...base, alertHook: { timeoutMs: MAX_ALERT_HOOK_TIMEOUT_MS } }).alertHook.timeoutMs,
    ).toBe(MAX_ALERT_HOOK_TIMEOUT_MS);

    expect(() => parseFileConfig({ ...base, requestTimeoutMs: MAX_REQUEST_TIMEOUT_MS + 1 })).toThrow(
      'config_invalid:requestTimeoutMs',
    );
    expect(() => parseFileConfig({ ...base, sendTimeoutMs: MAX_SEND_TIMEOUT_MS + 1 })).toThrow(
      'config_invalid:sendTimeoutMs',
    );
    expect(() =>
      parseFileConfig({ ...base, alertHook: { timeoutMs: MAX_ALERT_HOOK_TIMEOUT_MS + 1 } }),
    ).toThrow('config_invalid:alertHook.timeoutMs');
    // 溢出场景：超过有符号 32-bit 毫秒上沿
    expect(() => parseFileConfig({ ...base, requestTimeoutMs: 2_147_483_648 })).toThrow(
      'config_invalid:requestTimeoutMs',
    );
    expect(() => parseFileConfig({ ...base, sendTimeoutMs: 2_147_483_648 })).toThrow(
      'config_invalid:sendTimeoutMs',
    );
    expect(() => parseFileConfig({ ...base, alertHook: { timeoutMs: 2_147_483_648 } })).toThrow(
      'config_invalid:alertHook.timeoutMs',
    );
  });
});

describe('R21 alertHook.url scheme', () => {
  test('正控：http/https 与 null；负控：其余 scheme / 畸形 URL', () => {
    const dir = tempDir();
    const base = fileBase(dir);
    expect(parseFileConfig({ ...base, alertHook: { url: null } }).alertHook.url).toBeNull();
    expect(parseFileConfig({ ...base, alertHook: { url: 'https://hooks.example/a' } }).alertHook.url).toBe(
      'https://hooks.example/a',
    );
    expect(parseFileConfig({ ...base, alertHook: { url: 'http://127.0.0.1:9/x' } }).alertHook.url).toBe(
      'http://127.0.0.1:9/x',
    );
    expect(() => parseFileConfig({ ...base, alertHook: { url: 'ftp://evil.example/x' } })).toThrow(
      'config_invalid:alertHook.url',
    );
    expect(() => parseFileConfig({ ...base, alertHook: { url: 'file:///etc/passwd' } })).toThrow(
      'config_invalid:alertHook.url',
    );
    expect(() => parseFileConfig({ ...base, alertHook: { url: 'not-a-url' } })).toThrow(
      'config_invalid:alertHook.url',
    );
  });
});

describe('R21 .dirsync pre-wake removiability', () => {
  test('正控：自有 sticky .dirsync 可替换（writable）', () => {
    const root = tempDir();
    const sticky = join(root, 'sticky');
    mkdirSync(sticky, { mode: 0o1777 });
    expect(spawnSync('chmod', ['1777', sticky]).status).toBe(0);
    const path = join(sticky, 'dedup.json');
    writeFileSync(path, `${JSON.stringify({ records: {} })}\n`, { mode: 0o600 });
    writeFileSync(`${path}.dirsync`, `${sticky}\n`, { mode: 0o600 });
    expect(canReplaceDedupTarget(`${path}.dirsync`)).toBe(true);
    expect(inspectStateWritable(path)).toBe(true);
    expect(inspectDedupFile(path)).toEqual({ ok: false, reason: 'state_dirsync' });
  });

  test('负控：非 root 外属 sticky .dirsync 在 wake 前拒（有 root/sudo 才执行）', () => {
    const helper = fileURLToPath(new URL('./r21-dirsync-sticky.mjs', import.meta.url));
    const cwd = fileURLToPath(new URL('..', import.meta.url));
    const run = (cmd: string, args: string[]) =>
      spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 20_000 });

    let ran = run(process.execPath, [helper]);
    if (ran.status === 77 && `${ran.stdout}${ran.stderr}`.includes('SKIPPED:not_root')) {
      const sudoOk = run('sudo', ['-n', 'true']);
      if (sudoOk.status === 0) {
        ran = run('sudo', ['-n', process.execPath, helper]);
      }
    }
    const text = `${ran.stdout}${ran.stderr}`;
    if (ran.status === 77) {
      expect(text).toContain('SKIPPED:');
      return;
    }
    expect(ran.status).toBe(0);
    expect(text).toContain('PROOF:dirsync_irreplaceable');
    expect(text).toContain('PROOF:zero_wake_before_dirsync');
    expect(text).toContain('EXECUTED:uid=');
  });
});

describe('R21 non-loopback opt-in', () => {
  test('负控：非 loopback 无 opt-in 拒载；正控：显式 allowNonLoopback 可载并可听', async () => {
    const dir = tempDir();
    const base = fileBase(dir);
    expect(() => parseFileConfig({ ...base, listen: { host: '0.0.0.0', port: 0 } })).toThrow(
      'config_invalid:listen.allowNonLoopback',
    );
    const ok = parseFileConfig({
      ...base,
      listen: { host: '0.0.0.0', port: 0, allowNonLoopback: true },
    });
    expect(ok.listen).toEqual({ host: '0.0.0.0', port: 0, allowNonLoopback: true });

    const receiver = await startReceiver(
      testConfig({ listen: { host: '127.0.0.1', port: 0, allowNonLoopback: false } }, dir),
    );
    receivers.push(receiver);
    expect(receiver.url().startsWith('http://127.0.0.1:')).toBe(true);

    const open = await startReceiver(
      testConfig({ listen: { host: '0.0.0.0', port: 0, allowNonLoopback: true } }, dir),
    );
    receivers.push(open);
    expect(open.url()).toMatch(/^http:\/\/0\.0\.0\.0:\d+/);
  });
});
