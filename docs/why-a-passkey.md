# Why a passkey?

The Scribe keeps a signed record of your conversation — every turn, signed by
you and by the agent. Something has to hold the key that makes your side of
that record _yours_. That is what the passkey is for.

## What a passkey is

A passkey is a cryptographic key that lives in your device's secure hardware
and is unlocked with Touch ID (or Face ID, or your platform's equivalent). It
never leaves the device: this page can ask it to sign things, but can never
read, copy, or export it. There is no seed phrase to write down and nothing to
back up by hand — your platform keychain syncs it the way it syncs your other
passkeys.

## What it does here

Your passkey is the **root of your log**. It does not sign your chat messages —
it signs the _arrangements_:

- it endorses a per-session signing key held by your browser, which then signs
  each turn silently, and
- it authorizes the service to checkpoint ("seal") your log, in short-lived
  slices that always expire on their own.

Because the root key is yours and only signs with your touch, nobody — not the
operator, not this page — can quietly re-root your record or extend its
authority without you.

## When you'll actually be prompted

- **Two prompts to start** — create the passkey, then endorse this browser's
  signing key.
- **Two prompts to switch on receipts** — authorize sealing for your log.
- **An occasional "resume"** — sealing authority deliberately lapses after a
  few hours away; one approval renews it. The browser endorsement renews
  itself with a single prompt on your next message, roughly weekly.

Chatting itself never prompts. If something asks for Touch ID mid-conversation
and you didn't just press a button that says so, decline it.

## The browser-key alternative

You can start without a passkey. Your log is then rooted in a software key
that only this browser profile holds. Everything works the same day to day,
with one real difference: the root is only as safe as this browser profile,
and the choice is one-way — upgrading to a passkey later means resetting your
identity and starting a fresh log, because a log's root key cannot be swapped
after the fact. That immovability is a feature: it is exactly what stops
anyone else from swapping it either.

## Resetting

"Start fresh" forgets the identity this browser holds: wallet, keys, and your
local copy of the message text. It does not — and cannot — delete the log
entries already committed; those are permanent by design, though without your
local copy nobody can show what the committed hashes stand for. See
[how receipts work](./how-receipts-work.md).
