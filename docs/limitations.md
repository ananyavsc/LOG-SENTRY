# LogSentry: Known Limitations

## Tested on
Only a small synthetic log file (18 lines) and unit tests. No real-world logs and no labeled dataset were used, so no accuracy, precision or recall numbers are claimed.

## False negatives (attacks we can miss)
- Slow attacks: one attempt every 20 seconds is never caught by "5 failures in 60 seconds" (tested).
- Attacks spread across many IPs (distributed attacks), because we count per IP.
- Attacks that succeed on the first try (a stolen password), because we only look at failures.

## False positives (harmless activity we may flag)
- Many users behind one shared IP, such as an office or college network (tested).
- A user or script with a wrong saved password that keeps retrying.

## Other limits
- Only one log format (SSH-style authentication lines).
- Only one detection rule.
- One alert per IP per run, showing the largest window.

## Possible future work
- Rule for a successful login right after many failures.
- Rule for one IP trying many different usernames.
- Allow-list for trusted IPs.