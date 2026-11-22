// Browser APIs jsdom lacks, discovered one crash at a time in the challenge VM.
import { webcrypto } from 'node:crypto';
import { Worker as NodeWorker } from 'node:worker_threads';
import {
  ReadableStream, WritableStream, TransformStream,
  ByteLengthQueuingStrategy, CountQueuingStrategy,
} from 'node:stream/web';

export function installPolyfills(window, say = () => {}) {
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36';
  const def = (o, k, v) => { try { Object.defineProperty(o, k, { value: v, configurable: true, writable: true }); say(k); } catch {} };

  // Crash #5: the VM's feature battery reads ReadableStream.prototype.pipeTo.
  // Without streams it unwinds before xhr.send(), so these are load-bearing.
  for (const [k, v] of Object.entries({
    ReadableStream, WritableStream, TransformStream,
    ByteLengthQueuingStrategy, CountQueuingStrategy,
  })) {
    if (!window[k]) def(window, k, v);
  }
  if (!window.TextEncoder) def(window, 'TextEncoder', TextEncoder);
  if (!window.TextDecoder) def(window, 'TextDecoder', TextDecoder);

  Object.defineProperty(window.navigator, 'userAgent', { get: () => ua });
  Object.defineProperty(window.navigator, 'platform', { get: () => 'Win32' });
  Object.defineProperty(window.navigator, 'languages', { get: () => ['en-US', 'en'] });
  Object.defineProperty(window.navigator, 'language', { get: () => 'en-US' });
  Object.defineProperty(window.navigator, 'webdriver', { get: () => false });
  Object.defineProperty(window.navigator, 'hardwareConcurrency', { get: () => 8 });
  Object.defineProperty(window.navigator, 'deviceMemory', { get: () => 8 });
  Object.defineProperty(window.navigator, 'vendor', { get: () => 'Google Inc.' });
  Object.defineProperty(window.navigator, 'maxTouchPoints', { get: () => 0 });
  Object.defineProperty(window.navigator, 'userAgentData', { get: () => ({
    brands: [{ brand: 'Chromium', version: '157' }, { brand: 'Google Chrome', version: '157' }],
    mobile: false, platform: 'Windows',
    getHighEntropyValues: async () => ({ platform: 'Windows', platformVersion: '15.0.0', architecture: 'x86', bitness: '64', model: '', uaFullVersion: '157.0.0.0', fullVersionList: [{ brand: 'Chromium', version: '157.0.0.0' }] }),
  }) });
  for (const n of ['clipboard', 'permissions', 'mediaDevices', 'connection', 'storage', 'serviceWorker', 'geolocation']) {
    if (!(n in window.navigator)) Object.defineProperty(window.navigator, n, { get: () => ({}), configurable: true });
  }

  // --- viewport / screen (jsdom reports 0x0, which some fingerprint code bails on) ---
  const dim = (obj, props) => { for (const [k, v] of Object.entries(props)) { try { Object.defineProperty(obj, k, { get: () => v, configurable: true }); say('screen.' + k); } catch {} } };
  dim(window.screen, { width: 1440, height: 900, availWidth: 1440, availHeight: 900, colorDepth: 24, pixelDepth: 24, availLeft: 0, availTop: 0 });
  for (const [k, v] of Object.entries({ innerWidth: 1440, innerHeight: 900, outerWidth: 1440, outerHeight: 1000, screenX: 0, screenY: 0, screenLeft: 0, screenTop: 0, devicePixelRatio: 1 })) {
    try { Object.defineProperty(window, k, { get: () => v, configurable: true }); } catch {}
  }
  // --- document.fonts / timeline ---
  if (!window.document.fonts) {
    const fonts = {
      ready: Promise.resolve(), status: 'loaded', size: 0,
      check: () => true, load: () => Promise.resolve([]), add() {}, delete() {}, clear() {},
      forEach() {}, has: () => false, [Symbol.iterator]: function* () {},
      addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; },
    };
    try { Object.defineProperty(window.document, 'fonts', { value: fonts, configurable: true }); say('document.fonts'); } catch {}
  }
  if (!window.document.timeline) { try { Object.defineProperty(window.document, 'timeline', { value: { currentTime: 0, duration: null, playState: 'running', addEventListener() {}, removeEventListener() {} }, configurable: true }); say('document.timeline'); } catch {} }

  // --- Performance / Resource Timing ---
  {
    const perf = window.performance;
    const t0 = Date.now() - 850;
    const noop = () => {};
    perf.getEntries = () => [];
    perf.getEntriesByType = () => [];
    perf.getEntriesByName = () => [];
    perf.clearMarks = noop; perf.clearMeasures = noop; perf.clearResourceTimings = noop;
    perf.setResourceTimingBufferSize = noop;
    perf.mark = (n) => ({ name: n, entryType: 'mark', startTime: perf.now(), duration: 0 });
    perf.measure = (n) => ({ name: n, entryType: 'measure', startTime: 0, duration: 0 });
    if (!perf.timing) def(perf, 'timing', {
      navigationStart: t0, unloadEventStart: 0, unloadEventEnd: 0, redirectStart: 0, redirectEnd: 0,
      fetchStart: t0 + 5, domainLookupStart: t0 + 8, domainLookupEnd: t0 + 30, connectStart: t0 + 30,
      connectEnd: t0 + 90, secureConnectionStart: t0 + 60, requestStart: t0 + 95, responseStart: t0 + 180,
      responseEnd: t0 + 300, domLoading: t0 + 320, domInteractive: t0 + 600, domContentLoadedEventStart: t0 + 610,
      domContentLoadedEventEnd: t0 + 640, domComplete: t0 + 800, loadEventStart: t0 + 810, loadEventEnd: t0 + 830,
    });
    if (!perf.navigation) def(perf, 'navigation', { type: 0, redirectCount: 0 });
    if (!perf.memory) def(perf, 'memory', { jsHeapSizeLimit: 4294705152, totalJSHeapSize: 23456789, usedJSHeapSize: 18765432 });
  }

  if (!window.PerformanceObserver) {
    const PO = class PerformanceObserver {
      constructor(cb) { this._cb = cb; }
      observe() {}
      disconnect() {}
      takeRecords() { return []; }
      static get supportedEntryTypes() { return ['element', 'navigation', 'resource', 'mark', 'measure', 'paint', 'longtask', 'largest-contentful-paint', 'layout-shift', 'first-input', 'event']; }
    };
    def(window, 'PerformanceObserver', PO);
  }
  if (!window.PerformanceEntry) def(window, 'PerformanceEntry', class PerformanceEntry { constructor(i = {}) { Object.assign(this, i); } });
  if (!window.PerformanceResourceTiming) def(window, 'PerformanceResourceTiming', window.PerformanceEntry);

  // Crash #3: "WW[tu][(xW||xW)] is not a function" where xW='createObjectURL'
  // and WW[tu] === URL. jsdom has no Blob URL registry.
  const blobSources = new Map();
  {
    let n = 0;
    window.URL.createObjectURL = (blob) => {
      const u = `blob:https://www.fastpeoplesearch.com/${'0'.repeat(8)}-${(n++).toString(16)}`;
      blobSources.set(u, Promise.resolve(blob.text ? blob.text() : String(blob)));
      return u;
    };
    window.URL.revokeObjectURL = () => {};
    say('URL.createObjectURL');
  }
  // jsdom has no Web Workers. The VM spawns a probe worker from a blob URL.
  if (!window.Worker) {
    // Track workers so the harness can terminate them: a live NodeWorker keeps
    // the process alive after the VM is done with it.
    window.__cfWorkers = [];
    def(window, 'Worker', class Worker {
      constructor(url) {
        this.onmessage = null; this.onerror = null; this.onmessageerror = null;
        const src = blobSources.get(String(url));
        if (!src) { setTimeout(() => this.onerror && this.onerror({ message: 'no blob source' }), 0); return; }
        src.then((code) => {
          try {
            this._w = new NodeWorker(`
              const { parentPort } = require('node:worker_threads');
              globalThis.self = globalThis;
              globalThis.postMessage = (m) => parentPort.postMessage(m);
              globalThis.addEventListener = () => {};
              globalThis.removeEventListener = () => {};
              globalThis.close = () => process.exit(0);
              parentPort.on('message', (m) => { if (globalThis.onmessage) globalThis.onmessage({ data: m }); });
              ${code};
            `, { eval: true });
            this._w.unref?.();
            window.__cfWorkers.push(this._w);
            this._w.on('message', (m) => { if (this.onmessage) this.onmessage({ data: m }); });
            this._w.on('error', (e) => { if (this.onerror) this.onerror({ message: e.message, error: e }); });
          } catch (e) { if (this.onerror) this.onerror({ message: e.message }); }
        });
      }
      postMessage(m) { if (this._w) this._w.postMessage(m); }
      terminate() { if (this._w) this._w.terminate(); }
      addEventListener(t, f) { if (t === 'message') this.onmessage = f; if (t === 'error') this.onerror = f; }
      removeEventListener() {}
    });
  }

  if (window.crypto && !window.crypto.subtle) def(window.crypto, 'subtle', webcrypto.subtle);
  if (!window.fetch) def(window, 'fetch', globalThis.fetch);
  if (!window.Request) def(window, 'Request', globalThis.Request);
  if (!window.Response) def(window, 'Response', globalThis.Response);
  if (!window.Headers) def(window, 'Headers', globalThis.Headers);
  if (!window.structuredClone) def(window, 'structuredClone', globalThis.structuredClone);
  if (!window.matchMedia) def(window, 'matchMedia', (q) => ({ matches: false, media: q, onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } }));
  if (!window.ResizeObserver) def(window, 'ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  if (!window.IntersectionObserver) def(window, 'IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } });
  if (!window.requestIdleCallback) def(window, 'requestIdleCallback', (cb) => setTimeout(() => cb({ didTimeout: false, timeRemaining: () => 40 }), 1));
  if (!window.requestAnimationFrame) { def(window, 'requestAnimationFrame', (cb) => setTimeout(() => cb(Date.now()), 16)); def(window, 'cancelAnimationFrame', clearTimeout); }
  if (!window.reportError) def(window, 'reportError', (e) => console.log('reportError', e));
  if (!window.visualViewport) def(window, 'visualViewport', { width: 1440, height: 900, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: 0, scale: 1, onresize: null, onscroll: null, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } });
  if (!window.chrome) def(window, 'chrome', { runtime: {}, app: { isInstalled: false, InstallState: { DISABLED: 'disabled' }, RunningState: { RUNNING: 'running' } }, csi() {}, loadTimes() {} });
  if (!window.Notification) def(window, 'Notification', class { static permission = 'denied'; static requestPermission() { return Promise.resolve('denied'); } });
  if (!window.BroadcastChannel) def(window, 'BroadcastChannel', class { constructor() {} postMessage() {} close() {} addEventListener() {} });
  if (!window.MessageChannel) def(window, 'MessageChannel', class { constructor() { this.port1 = { postMessage() {}, onmessage: null, start() {}, close() {}, addEventListener() {}, removeEventListener() {} }; this.port2 = this.port1; } });
  if (!window.EventSource) def(window, 'EventSource', class { constructor() {} close() {} addEventListener() {} });

  // media / audio: Chrome exposes these constructors; Turnstile probes them
  if (!window.AudioContext) {
    const AC = class { constructor() { this.state = 'suspended'; this.sampleRate = 48000; this.currentTime = 0; this.destination = {}; this.listener = {}; }
      createOscillator() { return { type: 'sine', frequency: { value: 0, setValueAtTime() {} }, connect() {}, start() {}, stop() {}, disconnect() {}, addEventListener() {} }; }
      createGain() { return { gain: { value: 1, setValueAtTime() {}, linearRampToValueAtTime() {} }, connect() {}, disconnect() {} }; }
      createAnalyser() { return { fftSize: 2048, frequencyBinCount: 1024, getByteFrequencyData() {}, getFloatFrequencyData() {}, connect() {}, disconnect() {} }; }
      createDynamicsCompressor() { return { threshold: { value: -24 }, knee: { value: 30 }, ratio: { value: 12 }, attack: { value: 0.003 }, release: { value: 0.25 }, connect() {}, disconnect() {} }; }
      createScriptProcessor() { return { connect() {}, disconnect() {}, onaudioprocess: null }; }
      createBufferSource() { return { buffer: null, connect() {}, start() {}, stop() {}, disconnect() {}, addEventListener() {} }; }
      createBuffer(ch, len, rate) { return { numberOfChannels: ch, length: len, sampleRate: rate, getChannelData: () => new Float32Array(len), duration: len / rate }; }
      resume() { return Promise.resolve(); } suspend() { return Promise.resolve(); } close() { return Promise.resolve(); }
      addEventListener() {} removeEventListener() {} decodeAudioData() { return Promise.resolve({}); }
      getOutputTimestamp() { return { contextTime: 0, performanceTime: 0 }; }
    };
    def(window, 'AudioContext', AC); def(window, 'webkitAudioContext', AC);
  }
  if (!window.OfflineAudioContext) def(window, 'OfflineAudioContext', window.AudioContext);
  if (!window.MediaStream) def(window, 'MediaStream', class { constructor() { this.active = false; this.id = 'x'; } getTracks() { return []; } getAudioTracks() { return []; } getVideoTracks() { return []; } addEventListener() {} });
  if (!window.RTCPeerConnection) {
    const PC = class { constructor() { this.localDescription = null; this.iceConnectionState = 'new'; this.connectionState = 'new'; this.iceGatheringState = 'complete'; this.signalingState = 'stable'; }
      createDataChannel() { return { close() {}, send() {}, addEventListener() {} }; }
      createOffer() { return Promise.resolve({ type: 'offer', sdp: 'v=0' }); }
      createAnswer() { return Promise.resolve({ type: 'answer', sdp: 'v=0' }); }
      setLocalDescription() { return Promise.resolve(); } setRemoteDescription() { return Promise.resolve(); }
      addIceCandidate() { return Promise.resolve(); } getStats() { return Promise.resolve(new Map()); }
      close() {} addEventListener() {} removeEventListener() {} getSenders() { return []; } getReceivers() { return []; } getTransceivers() { return []; }
    };
    def(window, 'RTCPeerConnection', PC); def(window, 'webkitRTCPeerConnection', PC);
  }
  if (!window.SpeechSynthesisUtterance) def(window, 'SpeechSynthesisUtterance', class { constructor(t) { this.text = t; } });
  if (!window.speechSynthesis) def(window, 'speechSynthesis', { getVoices: () => [], speak() {}, cancel() {}, addEventListener() {} });
  if (!window.StorageManager) {} // noop
  if (!window.CSSStyleDeclaration) {} // noop
  if (!window.Permissions) {} // noop
}

// The challenge VM injects Turnstile's api.js, which defines globals the VM
// references (e.g. _fc5abb...). Without it the body encoder throws and is
// silently caught, so the request is opened but never sent.
export function serveTurnstile(ctx, apiBody) {
  return (request) => {
    const u = String(request.url);
    if (u.includes('/cdn-cgi/challenge-platform/')) return new Response(ctx.chl, { headers: { 'Content-Type': 'application/javascript' } });
    if (u.includes('challenges.cloudflare.com/turnstile/') && u.includes('api.js')) return new Response(apiBody, { headers: { 'Content-Type': 'application/javascript' } });
    return new Response('', { headers: { 'Content-Type': 'text/plain' } });
  };
}
