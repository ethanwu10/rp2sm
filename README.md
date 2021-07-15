# rp2sm

A rev/pwn challenge for [redpwnCTF 2021](https://github.com/redpwn/redpwnctf-2021-challenges).

Some rough notes I made for myself are in [notes.md](notes.md). The assembler
I wrote is in [assembler/assembler.hs](assembler/assembler.hs), and is used for
assembling the solutions in [solve/](solve/). Reproducible builds of challenge
artifacts are done with Docker; `make out` will build the binaries, and
`make pack/dist.tar` creates the tarball of files distrbuted to competitors.

[Author writeup](https://ethanwu.dev/blog/2021/07/14/redpwn-ctf-2021-rp2sm/)
