# Security policy

## Reporting a vulnerability

Please report security problems privately: open the repository's **Security** tab and choose **Report a vulnerability**
(GitHub's private vulnerability reporting). Do not open a public issue for something that could be exploited.

Include what you found, how to reproduce it and which version it affects (Settings → About shows it). You will get an
answer as soon as the maintainers can, and a fix goes into the next release; for a serious problem it also goes into a
new release the same day if possible.

## Supported versions

Only the newest release receives fixes. The `stable` branch and the `:stable` image follow full releases (30, 31, ...)
and are updated only when the next full release is published; see [Updating](docs/updating.md#stable-channel).

## What is already in place

[Hardening](docs/hardening.md) lists what the application does to protect itself, what is checked automatically on every
change, and what you should do when you run it.
