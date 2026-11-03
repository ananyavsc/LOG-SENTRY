# LogSentry Incident Report

Generated: 2026-11-03 18:20:47

Total incidents: 1

## Incident 1: Repeated failed logins

- **Source IP:** 203.0.113.50
- **Failed attempts:** 7
- **First seen:** 2026-11-02 10:15:32
- **Last seen:** 2026-11-02 10:15:50
- **Usernames tried:** admin, root

### What happened
The IP address 203.0.113.50 made 7 failed login attempts between 2026-11-02 10:15:32 and 2026-11-02 10:15:50, trying these usernames: admin, root. Many failures from one address in a short time is a common sign of a brute-force password guessing attempt.

### Detection rule
An alert is raised when one IP address has at least the configured number of failed logins inside the configured time window (default: 5 failures within 60 seconds).

### Evidence
```
2026-11-02 10:15:32 server01 sshd: Failed password for admin from 203.0.113.50 port 22
2026-11-02 10:15:35 server01 sshd: Failed password for admin from 203.0.113.50 port 22
2026-11-02 10:15:38 server01 sshd: Failed password for admin from 203.0.113.50 port 22
2026-11-02 10:15:41 server01 sshd: Failed password for root from 203.0.113.50 port 22
2026-11-02 10:15:44 server01 sshd: Failed password for root from 203.0.113.50 port 22
2026-11-02 10:15:47 server01 sshd: Failed password for admin from 203.0.113.50 port 22
2026-11-02 10:15:50 server01 sshd: Failed password for admin from 203.0.113.50 port 22
```
