# Rekor monitor for the dangerzone cert usage

Every signature that Dangerzone accepts for a container image must have a
matching entry in the Rekor transparency log.

This scripts monitors rekor and notifies us whenever a rekor entry matches
this key, so we can audit it.

Notification goes trough slack, using the "SLACK_WEBHOOK_URL" env variable.

Typical usage:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
  python rekor-monitor.py --slack
```
