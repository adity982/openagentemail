/**
 * #206 R9 父包装：不 import/mock imap，只复用已有 isolate 运输。
 * 子进程跑 11 组真实 route/core 与动作计数；主进程不得留下 imapflow mock。
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'bun:test';
import { runIsolatedChild } from './support/messages-list-rate-isolate.ts';

const MATRIX_FILE = join(import.meta.dir, 'support/wait-precedence-r9-matrix.ts');
/** 子套件含 DNS/截止用例，高于 list-rate 的 3.5s，仍远低于全量腿。 */
const R9_CHILD_TIMEOUT_MS = 20_000;

describe('#206 R9 撤销/断开优先级（隔离子进程）', () => {
  test('R9 矩阵子进程 12/0 且临时目录已回收', async () => {
    const result = await runIsolatedChild({
      argv: [process.execPath, 'test', MATRIX_FILE],
      timeoutMs: R9_CHILD_TIMEOUT_MS,
    });
    expect(result.timedOut).toBe(false);
    expect(result.exitCode).toBe(0);
    const childOut = `${result.stdout}\n${result.stderr}`;
    expect(childOut).toContain('12 pass');
    expect(childOut).toContain('0 fail');
    expect(existsSync(result.dataDir)).toBe(false);
  }, 25_000);
});
