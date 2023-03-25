# PWN

## Initialise Connection

Nothing to write about - just run `nc ip port`.
> HTB{g3t_r34dy_f0r_s0m3_pwn}

## Questionnaire

Using `file gs` see that the file is 64-bit, dynamically linked, not stripped & with `checksec` - NX enabled

```text
What is the name of the custom function that gets called inside `main()`? (e.g. vulnerable_function())
`vuln()`
What is the size of the 'buffer' (in hex or decimal)?
`0x20`
Which custom function is never called? (e.g. vuln())
`gg()`
What is the name of the standard function that could trigger a Buffer Overflow? (e.g. fprintf())
`fgets`
Insert 30, then 39, then 40 'A's in the program and see the output.
After how many bytes a Segmentation Fault occurs (in hex or decimal)?
40
(using printf 'A%.0s' {1..30} | ./test)
What is the address of 'gg()' in hex? (e.g. 0x401337)
```

To answer the last question use `objdump -d ./test` and find `0000000000401176 <gg>:`
I initially entered it with trailing zeroes and without 0x prefix and it wasn't accepted - had to change the answer to `0x401176`.

> HTB{th30ry_bef0r3_4cti0n}

## Getting Started

Run ./gs:

```text
      [Addr]       |      [Value]
-------------------+-------------------
0x00007fffffffe090 | 0x4242424241414141 <- Start of buffer
0x00007fffffffe098 | 0x0000000000000000
0x00007fffffffe0a0 | 0x0000000000000000
0x00007fffffffe0a8 | 0x0000000000000000
0x00007fffffffe0b0 | 0x6969696969696969 <- Dummy value for alignment
0x00007fffffffe0b8 | 0x00000000deadbeef <- Target to change
0x00007fffffffe0c0 | 0x0000555555555800 <- Saved rbp
0x00007fffffffe0c8 | 0x00007ffff7a03c87 <- Saved return address
0x00007fffffffe0d0 | 0x0000000000000001
0x00007fffffffe0d8 | 0x00007fffffffe1a8

Fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.
```

0x00007fffffffe0c0 - 0x00007fffffffe090 = 48
Modify wrapper.py setting `payload = b'A' * 48`, run and get the flag.

> HTB{b0f_s33m5_3z_r1ght?}
