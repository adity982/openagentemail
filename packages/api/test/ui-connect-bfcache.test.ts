/**
 * R4 a案：bfcache 复活不得带回 Connect reveal 明文。
 * 仓库无 jsdom；抽出 clearConnectSensitiveState + pagehide/pageshow 监听体，
 * 用可控 window/DOM 模拟 persisted 往返并断言明文不复活。
 */
import { describe, expect, test } from 'bun:test';

const { CONNECT_PAGE_JS } = await import('../src/ui/client/pages/connect.ts');

function extractClearConnectSensitiveState(): string {
  const start = CONNECT_PAGE_JS.indexOf('function clearConnectSensitiveState(');
  const end = CONNECT_PAGE_JS.indexOf('async function loadConnectPage(');
  if (start < 0 || end <= start) throw new Error('clearConnectSensitiveState slice missing');
  return CONNECT_PAGE_JS.slice(start, end);
}

/** 抽出 pagehide / pageshow 注册块（含 R4 a案监听）。 */
function extractBfcacheListeners(): string {
  const marker = "window.addEventListener('pagehide'";
  const start = CONNECT_PAGE_JS.indexOf(marker);
  if (start < 0) throw new Error('pagehide listener missing');
  return CONNECT_PAGE_JS.slice(start);
}

type Harness = {
  connectLoadGen: { value: number };
  connectCredentialValue: { value: string };
  connectRevealed: { value: boolean };
  connectTokenText: { value: string };
  connectTokenRevealText: { value: string };
  connectTokenCopyDisabled: { value: boolean };
  dispatchPagehide: () => void;
  dispatchPageshow: (persisted: boolean) => void;
};

function makeHarness(): Harness {
  const box: {
    connectLoadGen?: { value: number };
    connectCredentialValue?: { value: string };
    connectRevealed?: { value: boolean };
    connectTokenText?: { value: string };
    connectTokenRevealText?: { value: string };
    connectTokenCopyDisabled?: { value: boolean };
    dispatchPagehide?: () => void;
    dispatchPageshow?: (persisted: boolean) => void;
  } = {};

  new Function(
    'box',
    `
      var connectLoadGen = 0;
      var connectCredentialValue = 'oa_bfcache-secret';
      var connectEndpointValue = 'https://mail.example/mcp';
      var connectRevealed = true;
      var connectToken = { textContent: 'oa_bfcache-secret' };
      var connectTokenReveal = {
        textContent: 'Hide',
        setAttribute: function () {},
      };
      var connectTokenCopy = {
        disabled: false,
        title: '',
        removeAttribute: function () {},
      };
      var connectEndpoint = { textContent: 'https://mail.example/mcp' };
      var connectIdentity = { textContent: 'fox@test.example' };
      var connectCredential = { hidden: false };
      var connectCards = { replaceChildren: function () {} };
      var listeners = { pagehide: null, pageshow: null };
      var window = {
        addEventListener: function (type, fn) {
          listeners[type] = fn;
        },
      };
      ${extractClearConnectSensitiveState()}
      ${extractBfcacheListeners()}
      box.connectLoadGen = {
        get value() { return connectLoadGen; },
      };
      box.connectCredentialValue = {
        get value() { return connectCredentialValue; },
        set value(v) { connectCredentialValue = v; },
      };
      box.connectRevealed = {
        get value() { return connectRevealed; },
        set value(v) { connectRevealed = v; },
      };
      box.connectTokenText = {
        get value() { return connectToken.textContent; },
        set value(v) { connectToken.textContent = v; },
      };
      box.connectTokenRevealText = {
        get value() { return connectTokenReveal.textContent; },
      };
      box.connectTokenCopyDisabled = {
        get value() { return connectTokenCopy.disabled; },
      };
      box.dispatchPagehide = function () {
        listeners.pagehide({ persisted: true });
      };
      box.dispatchPageshow = function (persisted) {
        listeners.pageshow({ persisted: persisted });
      };
    `,
  )(box);

  return box as Harness;
}

describe('Connect page bfcache reveal guard (R4)', () => {
  test('pagehide clears plaintext via clearConnectSensitiveState', () => {
    const box = makeHarness();
    expect(box.connectCredentialValue.value).toBe('oa_bfcache-secret');
    expect(box.connectRevealed.value).toBe(true);
    expect(box.connectTokenText.value).toBe('oa_bfcache-secret');

    box.dispatchPagehide();

    // pagehide 后堆内无明文，代际自增，DOM 回遮蔽
    expect(box.connectCredentialValue.value).toBe('');
    expect(box.connectRevealed.value).toBe(false);
    expect(box.connectTokenText.value).toBe('••••••••••••');
    expect(box.connectLoadGen.value).toBe(1);
    expect(box.connectTokenCopyDisabled.value).toBe(true);
  });

  test('pageshow persisted resets reveal; plaintext must not resurrect', () => {
    const box = makeHarness();
    box.dispatchPagehide();

    // 负控/敌对：模拟异常恢复路径试图把明文写回堆与 DOM
    box.connectCredentialValue.value = 'oa_bfcache-secret';
    box.connectRevealed.value = true;
    box.connectTokenText.value = 'oa_bfcache-secret';

    box.dispatchPageshow(true);

    // persisted 复活必须清敏感态并强制回遮蔽；明文不得留在堆或 DOM
    expect(box.connectCredentialValue.value).toBe('');
    expect(box.connectRevealed.value).toBe(false);
    expect(box.connectTokenText.value).toBe('••••••••••••');
    expect(box.connectTokenRevealText.value).toBe('Reveal');
    expect(box.connectTokenCopyDisabled.value).toBe(true);
    expect(box.connectTokenText.value).not.toBe('oa_bfcache-secret');
    expect(box.connectLoadGen.value).toBe(2); // pagehide + pageshow 各自增一次
  });

  test('pageshow without persisted leaves reveal state alone', () => {
    const box = makeHarness();
    // 首次 pageshow persisted=false 不得误清（正常导航进入）
    box.dispatchPageshow(false);
    expect(box.connectCredentialValue.value).toBe('oa_bfcache-secret');
    expect(box.connectRevealed.value).toBe(true);
    expect(box.connectTokenText.value).toBe('oa_bfcache-secret');
  });
});
