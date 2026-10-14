## What does this PR do?

<!-- One or two sentences. Link the issue if there is one: `Closes #123`. -->

## Type of change

- [ ] fix (a defect in released behaviour)
- [ ] feat (new capability)
- [ ] chore / docs (no behaviour change)
- [ ] breaking change (see "Compatibility" below)

## How was it verified?

<!-- Not "I checked": the commands you ran, and what they printed. For
     anything touching a live system: the state read BACK after the write.
     A control that cannot fail proves nothing — show it rejecting, too. -->

```
$ 
```

## Compatibility

<!-- Does `ceffio install` run twice still converge? Does an existing
     deployment upgrade cleanly? If a migration is needed, describe it. -->

## Rules checklist

- [ ] `gofmt -l .` prints nothing; `make build vet test` pass locally
- [ ] No real IP, real domain, account name or secret anywhere in the diff (placeholders only)
- [ ] New images are pinned (no `latest`); the version registry test passes
- [ ] New secrets go through OpenBao — no Kubernetes Secret, no printed value
- [ ] Deployment steps are idempotent and documented with their WHY
- [ ] Quoted outputs from other tools are kept verbatim
