# Security Policy

## Supported versions

Only the latest release is maintained. Older versions in `Releases/` are kept for reference
and receive no fixes.

## What is in scope

This plugin runs inside Cheat Engine and reads memory from a process you have already
attached to. Relevant problems are therefore things that could hurt the person running it:

- a crafted target process causing the plugin to crash Cheat Engine, or to read or write
  outside its own buffers
- the generated Auto Assembler script patching an address other than the one it verified
- `SigMaker.ini` being read or written somewhere unintended

Reading memory from another process is what this tool is for. That is not a vulnerability.

## What is out of scope

Anti-cheat detection, bans, and anything about using the plugin against a particular game.
Cheat Engine's own behaviour — report that to the Cheat Engine project.

## Reporting

Open a [private security advisory](https://github.com/gmax29/SigMakerPlugin/security/advisories/new),
or write to the address on the maintainer's GitHub profile. Please do not open a public
issue for a memory-safety problem until it is fixed.

Useful details: the Cheat Engine version, whether the target is 32 or 64 bit, the address
or function you were working on, and the generated signature or script if there was one.

This is a hobby project maintained by one person. There is no bounty and no guaranteed
response time, but reports are taken seriously and you will get an answer.
