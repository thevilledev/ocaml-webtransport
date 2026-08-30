# Third-party provenance

Parts of purequic were ported from or written against
[anmonteiro/ocaml-quic](https://github.com/anmonteiro/ocaml-quic)
(Copyright (c) 2020 António Nuno Monteiro), distributed under the
BSD-3-Clause license. The full license text is in that repository's
`LICENSE`; the redistribution conditions are reproduced here:

> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are
> met: (1) redistributions of source code must retain the above copyright
> notice, this list of conditions and the following disclaimer;
> (2) redistributions in binary form must reproduce the above copyright
> notice, this list of conditions and the following disclaimer in the
> documentation and/or other materials provided with the distribution;
> (3) neither the name of the copyright holder nor the names of its
> contributors may be used to endorse or promote products derived from
> this software without specific prior written permission.
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
> "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.

Ported material, by file:

- `qkdf.ml`, `aead.ml` — key-derivation label construction, AEAD nonce
  construction and the Retry integrity constants follow ocaml-quic's
  `lib/crypto.ml` (rewritten against mirage-crypto 2.x / kdf APIs).
- `test/purequic/test_purequic.ml` (in the repository root's `test/`
  tree) — the RFC 9001 Appendix A hex vectors were extracted from
  ocaml-quic's `lib_test/test_packet_protection.ml` (they are also
  printed verbatim in RFC 9001 itself).
- The RFC 9002 recovery module planned for milestone P3 will port
  ocaml-quic's `lib/recovery.ml` and its `lib_test/test_rfc9002.ml`
  vector suite; this notice covers those files when they land.
