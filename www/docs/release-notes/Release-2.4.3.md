# Release 2.4.3 `20th July 2026`

This point release hardens `auth_hmac` against clock steps, where a forward step
stranded both the sender and its receivers past the freshness window and turned
a transient time error into a lasting dual active. The signed input is
unchanged, so a 2.4.3 node interoperates with a 2.4.2 node.

## Improvements

- **vrrp**: sign the `auth_hmac` trailer once per advertisement, so the copies
  sent to unicast peers share one sequence and HMAC and cost one HMAC per
  advertisement instead of one per peer. Pointed out by Aditya Dogra.

## Fixes

- **vrrp**: recover the `auth_hmac` sequence after a corrected clock step. Time
  mode restarts from the clock once the stored timestamp runs past the freshness
  window. Monotonic mode keeps strict growth. Pointed out by Aditya Dogra.

- **vrrp**: expire an `auth_hmac` replay mark outside the freshness window, so a
  receiver stops rejecting a sender that recovered from a step. Monotonic mode
  keeps its mark. Pointed out by Aditya Dogra.
