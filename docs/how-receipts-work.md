# How receipts work

Every turn of a Scribe conversation — your message, and the agent's reply —
is committed to an append-only transparency log whose growth is anchored by an
on-chain contract. A **receipt** is the proof that a particular turn is in
that log. You hold your receipts; the log holds only commitments.

## Signed both ways

Each turn produces two signed statements: you sign your input, the agent signs
its reply. Neither side can later deny what it said, and neither can edit the
record — the log only ever grows.

## Your words never leave your browser

What reaches the public log is a _commitment_ — a salted hash — not your text.
A stranger reading the log learns that turns happened, in what order, and
nothing else. The only copy of your message text that can open those hashes
lives in this browser ("your copy"). That is why deleting your copy is
irreversible: the log entries remain forever, but without your copy nobody —
including you — can show what they stand for. Download your receipts first if
you want to keep that ability.

## "Receipting…" and "receipted"

When you send a turn it is admitted immediately, then works its way into the
log: registered, sequenced into the tree, and finally covered by a sealed,
on-chain-anchored checkpoint. The caption under a message tracks exactly that:
**receipting…** while the entry is in flight, **receipted** once its receipt
has been collected, and **verified** once this browser has re-checked the
receipt's cryptography for itself.

## Offline, forever

Receipts verify against public information — a root public key and the
receipt's own contents. No account, no API call, no cooperation from the
operator. Download your receipts and run:

```
node scripts/verify-receipts.mjs --export <downloaded-file>
```

with the service switched off entirely, years from now, and the answer is the
same. If anyone — including the operator — alters the stored conversation,
re-verification fails: the proof does not depend on trusting the party that
kept the record.
