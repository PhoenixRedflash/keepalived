# Release 2.4.2 `7th July 2026`

This point release continues the `auth_hmac` work from 2.4.0 and 2.4.1. It fixes
IPv6 verification, which never worked, and adds a receive-only mode that makes
rolling the extension onto a running cluster hitless. The signed input changed
again, so adverts from a 2.4.0 or 2.4.1 node no longer verify. Every node in a
virtual router that uses `auth_hmac` must run the same version, so upgrade them
together. No other component is affected.

## New

- **vrrp**: add a receive-only `auth_hmac` mode that verifies a present trailer
  but sends none. A cluster can now migrate receive-only, then permissive, then
  enforce, with every sweep hitless. permissive on its own risked dual active,
  since a reloaded node signed toward peers that could not yet verify. Suggested
  by Aditya Dogra.

## Fixed

- **vrrp**: IPv6 `auth_hmac` dropped every signed advert. The kernel writes the
  IPv6 checksum after the trailer is signed, so a receiver that hashed the packet
  as received never matched the sender. The VRRP checksum and HMAC fields are now
  read as zero on both sides, which removes the asymmetry, as the IETF draft now
  specifies. Reported by Aditya Dogra.
