# html-preview-poc

Authorized security-research demonstrator. It exists to answer one question
during a code review of a sandboxed HTML-preview feature:

> If external scripts are permitted by allowlisting CDN **origins**
> (`cdn.jsdelivr.net`, `unpkg.com`, `cdnjs.cloudflare.com`, `esm.sh`) and the
> server attaches Subresource Integrity hashes that it computes by downloading
> the file at render time, does that actually constrain **which code** is
> allowed to run?

`poc.js` is the control. It is an ordinary file in an ordinary public GitHub
repository owned by the tester, reachable over
`https://cdn.jsdelivr.net/gh/<owner>/html-preview-poc@main/poc.js`. jsDelivr
serves any public repository on any branch, with no release, review or
approval. The allowlisted origin therefore says nothing whatsoever about who
wrote the file behind it.

## What it reports

Loaded into the preview, `poc.js` prints a panel containing:

1. **Proof of execution** — the URL it came from and a timestamp.
2. **What the embedding server did to its own `<script>` tag** — in
   particular whether the server generated an `integrity` attribute for it.
   A hash minted at render time over bytes fetched at render time cannot
   detect a compromised CDN: if the CDN serves modified bytes, the server
   hashes the modified bytes and publishes that hash as a guarantee.
3. **An egress matrix** — which outbound channels the sandbox CSP really
   blocks (`fetch`, `<img>`, `sendBeacon`, cookies, `localStorage`) and which
   survive it.

## Scope and conduct

This is a read-only demonstrator.

- No obfuscation. Everything it does is readable in `poc.js`.
- It reads no credentials, cookies, storage or user input.
- It renders no sign-in, consent or payment UI of any kind.
- It contacts no host belonging to the tester. The single network probe is a
  WebRTC reachability check against Google's public STUN server, and its
  result is printed on screen rather than transmitted.

Run only against systems you are authorized to test. This repository was
created for an authorized review of an internal pre-production environment at
the request of the owning engineering team, and should be deleted once the
finding is resolved.

## Note on WebRTC

The egress matrix usually shows `fetch`, `<img>` and `sendBeacon` correctly
blocked by `connect-src 'none'` / `img-src data: blob:`, while
`RTCPeerConnection` still constructs and gathers ICE candidates with no CSP
violation recorded. This is expected: `connect-src` does not govern WebRTC.
CSP Level 3 added a separate `webrtc` directive for exactly this gap, so a
policy that relies on `connect-src 'none'` to prevent data egress should also
set `webrtc 'block'`.

## Remediation this supports

- Pin **exact URLs**, not origins. CSP `script-src` accepts a full path and
  matches it exactly when the path does not end in `/`.
- Derive SRI hashes from a reviewed constant or lockfile, never from a
  download performed at render time, and never overwrite an author-supplied
  `integrity` value.
- Add `webrtc 'block'` alongside `connect-src 'none'`.
- Parse HTML with a real parser rather than regular expressions before
  rewriting tags.

