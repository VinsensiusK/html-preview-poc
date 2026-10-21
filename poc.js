/*!
 * html-preview-poc - authorized security-research demonstrator
 * ------------------------------------------------------------
 * Question this answers:
 *
 *   If a sandboxed HTML preview allows external scripts by allowlisting CDN
 *   *origins* (cdn.jsdelivr.net, unpkg.com, ...) and attaches SRI hashes that
 *   the server computes by downloading the file at render time, does that
 *   actually constrain which code is allowed to run?
 *
 * This file is the control. It lives in an ordinary public GitHub repository
 * owned by the tester and is reached over https://cdn.jsdelivr.net/gh/...,
 * which is an allowlisted origin. Nothing about that origin says anything
 * about who wrote this file.
 *
 * It reports three things into the page:
 *   1. that it executed at all, and where it was loaded from;
 *   2. whether the embedding server generated an `integrity` attribute for
 *      it - i.e. whether it stamped a hash onto code it had never reviewed;
 *   3. which egress channels the sandbox CSP actually blocks.
 *
 * BENIGN BY DESIGN
 *   - No obfuscation; everything it does is readable below.
 *   - Reads no credentials, cookies, storage or user input.
 *   - Renders no login or consent UI of any kind.
 *   - Contacts no host belonging to the tester. The one network probe is a
 *     WebRTC connectivity check against Google's public STUN server, and its
 *     result is printed on screen rather than sent anywhere.
 *
 * Authorized review of an internal pre-production environment, at the request
 * of the owning engineering team. Delete this repository once the finding is
 * resolved.
 */
(function () {
  'use strict';

  var OUT_ID = 'poc-out';
  var rows = [];
  var violations = [];

  function row(label, value, flag) {
    rows.push({ label: label, value: String(value), flag: flag || '' });
    render();
  }

  window.addEventListener('securitypolicyviolation', function (e) {
    violations.push(e.violatedDirective + '  <-  ' + String(e.blockedURI).slice(0, 60));
    render();
  });

  /* ---------------------------------------------------------------- *
   * 1. Proof of execution + what the server did to our script tag
   * ---------------------------------------------------------------- */

  // document.currentScript is null by the time async callbacks run, so grab
  // the tag up front.
  var self = document.currentScript || (function () {
    var all = document.getElementsByTagName('script');
    for (var i = all.length - 1; i >= 0; i--) {
      if ((all[i].src || '').indexOf('html-preview-poc') !== -1) return all[i];
    }
    return null;
  })();

  var selfSrc = self ? self.src : '(unknown)';
  var selfIntegrity = self ? (self.getAttribute('integrity') || '') : '';
  var selfCrossOrigin = self ? (self.getAttribute('crossorigin') || '') : '';

  /* ---------------------------------------------------------------- *
   * 2. Egress matrix - what does the sandbox CSP really stop?
   * ---------------------------------------------------------------- */

  function probeFetch() {
    try {
      fetch('https://example.com/probe')
        .then(function () { row('fetch() to https', 'ALLOWED', 'bad'); })
        .catch(function (e) { row('fetch() to https', 'blocked (' + e.name + ')', 'good'); });
    } catch (e) {
      row('fetch() to https', 'blocked (' + e.name + ')', 'good');
    }
  }

  function probeImage() {
    try {
      var img = new Image();
      img.onload = function () { row('<img> to https', 'ALLOWED', 'bad'); };
      img.onerror = function () { row('<img> to https', 'blocked', 'good'); };
      img.src = 'https://example.com/probe.png';
    } catch (e) {
      row('<img> to https', 'blocked (' + e.name + ')', 'good');
    }
  }

  function probeBeacon() {
    try {
      var queued = navigator.sendBeacon('https://example.com/probe', 'x');
      // sendBeacon returns true when the request is merely queued; a
      // connect-src violation in the list below is what proves it was
      // actually stopped.
      row('navigator.sendBeacon', 'returned ' + queued + ' (see violations)', queued ? '' : 'good');
    } catch (e) {
      row('navigator.sendBeacon', 'threw ' + e.name, 'good');
    }
  }

  function probeOrigin() {
    var origin;
    try { origin = String(document.origin); } catch (e) { origin = 'threw ' + e.name; }
    row('document.origin', origin, origin === 'null' || origin === 'undefined' ? 'good' : '');

    try {
      void document.cookie;
      row('document.cookie', 'READABLE', 'bad');
    } catch (e) {
      row('document.cookie', 'blocked (' + e.name + ')', 'good');
    }

    try {
      localStorage.getItem('probe');
      row('localStorage', 'ACCESSIBLE', 'bad');
    } catch (e) {
      row('localStorage', 'blocked (' + e.name + ')', 'good');
    }
  }

  // The interesting one: CSP `connect-src` does not govern WebRTC. CSP Level 3
  // added a separate `webrtc` directive precisely to close this gap. If that
  // directive is absent, ICE gathering proceeds even under connect-src 'none'.
  // We only check reachability against a public STUN server and print what we
  // get; nothing is encoded into the probe and nothing is transmitted.
  function probeWebRtc() {
    if (typeof RTCPeerConnection === 'undefined') {
      row('RTCPeerConnection', 'unavailable', 'good');
      return;
    }
    var found = 0;
    var first = '';
    try {
      var pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
      });
      pc.createDataChannel('probe');
      pc.onicecandidate = function (e) {
        if (e.candidate && !found++) first = e.candidate.candidate.slice(0, 64);
      };
      pc.createOffer()
        .then(function (o) { return pc.setLocalDescription(o); })
        .then(function () { row('RTCPeerConnection', 'constructed, SDP offer created', 'bad'); })
        .catch(function (e) { row('RTCPeerConnection', 'failed ' + e.name, 'good'); });

      setTimeout(function () {
        row('WebRTC ICE candidates',
            found ? found + ' gathered - ' + first : 'none gathered',
            found ? 'bad' : 'good');
        try { pc.close(); } catch (e) {}
      }, 6000);
    } catch (e) {
      row('RTCPeerConnection', 'threw ' + e.name, 'good');
    }
  }

  /* ---------------------------------------------------------------- *
   * 3. Render
   * ---------------------------------------------------------------- */

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function render() {
    var host = document.getElementById(OUT_ID);
    if (!host) return;

    var verdict = selfIntegrity
      ? '<p class="poc-bad"><b>The server generated an SRI hash for this file.</b> '
        + 'It downloaded code from an attacker-controlled repository, hashed whatever '
        + 'arrived, and published that hash as an integrity guarantee.</p>'
      : '<p class="poc-bad"><b>This file was served with no integrity attribute at all.</b></p>';

    var body = rows.map(function (r) {
      var cls = r.flag === 'bad' ? 'poc-bad' : (r.flag === 'good' ? 'poc-good' : '');
      return '<tr><td>' + esc(r.label) + '</td><td class="' + cls + '">' + esc(r.value) + '</td></tr>';
    }).join('');

    host.innerHTML =
      '<style>'
      + '.poc{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;border:2px solid #b00;'
      + 'border-radius:6px;padding:14px;margin:10px 0;background:#fff8f8;color:#111}'
      + '.poc h2{margin:0 0 4px;font-size:15px;color:#b00}'
      + '.poc table{border-collapse:collapse;width:100%;margin-top:8px}'
      + '.poc td{border-top:1px solid #e3c7c7;padding:3px 6px;vertical-align:top}'
      + '.poc td:first-child{width:24ch;color:#555}'
      + '.poc-bad{color:#b00;font-weight:600}.poc-good{color:#176b2c}'
      + '.poc pre{background:#f3eaea;padding:6px;overflow:auto;white-space:pre-wrap;margin:6px 0 0}'
      + '.poc .src{word-break:break-all;font-size:12px;color:#333}'
      + '</style>'
      + '<div class="poc">'
      + '<h2>Security PoC &mdash; third-party code executed in this preview</h2>'
      + '<div class="src">loaded from: ' + esc(selfSrc) + '</div>'
      + '<div class="src">executed at: ' + esc(new Date().toISOString()) + '</div>'
      + '<table>'
      + '<tr><td>integrity attribute</td><td class="' + (selfIntegrity ? 'poc-bad' : '') + '">'
      + esc(selfIntegrity || '(none)') + '</td></tr>'
      + '<tr><td>crossorigin</td><td>' + esc(selfCrossOrigin || '(none)') + '</td></tr>'
      + body
      + '</table>'
      + verdict
      + '<p>Egress channels marked in red are reachable despite the sandbox CSP. '
      + 'Channels in green are correctly blocked.</p>'
      + '<pre>CSP violations observed:\n' + esc(violations.join('\n') || '(none yet)') + '</pre>'
      + '</div>';
  }

  function start() {
    if (!document.getElementById(OUT_ID)) {
      var d = document.createElement('div');
      d.id = OUT_ID;
      document.body.appendChild(d);
    }
    render();
    probeFetch();
    probeImage();
    probeBeacon();
    probeOrigin();
    probeWebRtc();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();

