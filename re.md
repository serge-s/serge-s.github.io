# Reverse Engineering

## Needle in a Haystack

Plain text flag in the binary.

> HTB{d1v1ng_1nt0_th3_d4tab4nk5}

## Shattered Tablet

Thanks to IDA's decompiler got this (had to help it determining the array size):

```c
  if ( s[31] == 'p'
    && s[1] == 'T'
    && s[7] == 'k'
    && s[36] == 'd'
    && s[11] == '4'
    && s[20] == 'e'
    && s[10] == '_'
    && s[0] == 'H'
    && s[34] == 'r'
    && s[35] == '3'
    && s[25] == '_'
    && s[2] == 'B'
    && s[29] == 'r'
    && s[3] == '{'
    && s[26] == 'b'
    && s[5] == 'r'
    && s[13] == '4'
    && s[30] == '3'
    && s[19] == 'v'
    && s[12] == 'p'
    && s[33] == '1'
    && s[27] == '3'
    && s[17] == 'n'
    && s[4] == 'b'
    && s[32] == '4'
    && s[9] == 'n'
    && s[16] == ','
    && s[8] == '3'
    && s[6] == '0'
    && s[23] == 't'
    && s[15] == 't'
    && s[24] == '0'
    && s[14] == 'r'
    && s[37] == '}'
    && s[21] == 'r'
    && s[22] == '_'
    && s[18] == '3'
    && s[28] == '_' )
  {
    puts("Yes! That's right!");
  }
```

Just sort these in ascending order and get the flag:
> HTB{br0k3n_4p4rt,n3ver_t0_b3_r3p41r3d}

## She Shells C Shells

Again, use IDA to decompile it:

```c
  while ( 1 )
  {
    printf("ctfsh-$ ");
    if ( !fgets(s, 1024, stdin) )
      break;
    v7 = strchr(s, 10);
    if ( v7 )
      *v7 = 0;
    runcmd(s);
  }
```

`runcmd` looks up `CMDS` where we notice a `getflag` command with the matching `func_flag()` function:

```c
int func_flag()
{
  char s[256] = {};
  unsigned int j;
  unsigned int i;

  printf("Password: ");

  fgets(s, 256, stdin);
  for ( i = 0; i <= 76; ++i )
    s[i] ^= m1[i];
  if ( memcmp(s, t, 77) )
    return -1;
  for ( j = 0; j <= 76; ++j )
    s[j] ^= m2[j];
  printf("Flag: %s\n", s);
  return 0;
}
```

`s` is the entered password
`s ^ m1` should be equal to `t` and then decoded flag is calculated as `s ^ m2`
Which means we can just XOR `m2` and `t` to get the flag:

```c
#include <stdio.h>

unsigned char m2[] = {
0x64, 0x1E, 0x0F5, 0x0E2, 0x0C0, 0x97, 0x44, 0x1B, 0x0F8, 0x5F,
0x0F9, 0x0BE, 0x18, 0x5D, 0x48, 0x8E, 0x91, 0x0E4, 0x0F6, 0x0F1,
0x5C, 0x8D, 0x26, 0x9E, 0x2B, 0x0A1, 0x2, 0x0F7, 0x0C6, 0x0F7,
0x0E4, 0x0B3, 0x98, 0x0FE, 0x57, 0x0ED, 0x4A, 0x4B, 0x0D1, 0x0F6,
0x0A1, 0x0EB, 0x9, 0x0C6, 0x99, 0x0F2, 0x58, 0x0FA, 0x0CB, 0x6F,
0x6F, 0x5E, 0x1F, 0x0BE, 0x2B, 0x13, 0x8E, 0x0A5, 0x0A9, 0x99,
0x93, 0x0AB, 0x8F, 0x70, 0x1C, 0x0C0, 0x0C4, 0x3E, 0x0A6, 0x0FE,
0x93, 0x35, 0x90, 0x0C3, 0x0C9, 0x10, 0x0E9};

unsigned char t[] = {
0x2C, 0x4A,0x0B7, 0x99,0x0A3,0E5, 0x70, 0x78, 0x93, 0x6E, 0x97,
0x0D9, 0x47, 0x6D, 0x38,0x0BD,0x0FF, 0x0BB, 0x85, 0x99, 0x6F,0E1,
0x4A, 0x0AB, 0x74,0x0C3, 0x7B,0x0A8, 0x0B2, 0x9F,0x0D7,0x0EC,0x0EB,
0x0CD, 0x63,0x0B2, 0x39, 0x23,0E1, 0x84, 0x92, 0x96, 0x9,0x0C6,
0x99,0x0F2, 0x58,0x0FA,0x0CB, 0x6F, 0x6F, 0x5E, 0x1F,0x0BE, 0x2B,
0x13, 0x8E,0x0A5,0x0A9, 0x99, 0x93,0x0AB, 0x8F, 0x70, 0x1C,0x0C0,
0x0C4, 0x3E,0x0A6,0x0FE, 0x93, 0x35, 0x90,0x0C3,0x0C9, 0x10,0E9};

void main()
{
    for (int i = 0; i < 77; i++)
    {
        printf("%c", m2[i] ^ t[i]);
    }
}
```

> HTB{cr4ck1ng_0p3n_sh3ll5_by_th3_s34_sh0r3}

## Hunting License

Yes, fire up IDA again.

3 passwords:

1. `strcmp(s1, "PasswordNumeroUno")`

2. `reverse(s2, "0wTdr0wss4P", 11);`
which gives 'P4ssw0rdTw0'

3. `xor(v0, &t2, 17, 19);`
where 17 is the string length and 19 is the value to XOR with.

```c
#include <stdio.h>

unsigned char t2[] = {0x47, 0x7B, 0x7A, 0x61, 0x77, 0x52, 0x7D, 0x77, 0x55, 0x7A, 0x7D, 0x72, 0x7F, 0x32, 0x32, 0x32, 0x13};

void main()
{
    for (int i = 0; i < 17; i++)
    {
        printf("%c", t2[i] ^ 19);
    }
}
```

Which gives us the 3rd password: ThirdAndFinal!!!

Now launch the container and answer its questions:

```text
What is the file format of the executable?
> ELF
[+] Correct!

What is the CPU architecture of the executable?
> X86
[+] Correct!

What library is used to read lines for user answers? (`ldd` may help)
> readline
[+] Correct!

What is the address of the `main` function?
> 0x401172
[+] Correct!

How many calls to `puts` are there in `main`? (using a decompiler may help)
> 5
[+] Correct!

What is the first password?
> PasswordNumeroUno
[+] Correct!

What is the reversed form of the second password?
> 0wTdr0wss4P
[+] Correct!

What is the real second password?
> P4ssw0rdTw0
[+] Correct!

What is the XOR key used to encode the third password?
> 19
[+] Correct!

What is the third password?
> ThirdAndFinal!!!
[+] Correct!

[+] Here is the flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`
```

> HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}

## Cave System

Thanks to old friend IDA, decompiled C code:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[128] = {};
  printf("What route will you take out of the cave? ");
  fgets(s, 128, stdin);
  if ( !memcmp(s, "HTB{", 4uLL)
    && s[48] * s[21] == 20
    && s[32] - s[36] == 0xFA
    && s[37] - s[26] == 0xD6
    && s[16] - s[48] == 8
    && s[55] - s[8] == 0xD5
    && s[7] * s[26] == 0xED
    && s[24] * s[4] == 0xC8
    && (s[28] ^ s[34]) == 85
    && s[30] - s[55] == 52
    && s[50] + s[59] == 0x8F
    && s[27] + s[44] == 0xD6
    && (s[14] ^ s[17]) == 49
    && s[20] * s[56] == 0xAC
    && s[58] - s[26] == 0xC2
    && (s[6] ^ s[26]) == 47
    && (s[39] ^ s[14]) == 90
    && (s[39] ^ s[44]) == 64
    && s[40] == s[26]
    && s[49] + s[23] == 0x98
    && s[59] * s[23] == 104
    && s[1] - s[28] == 0xDB
    && s[24] - s[29] == 0xD2
    && s[38] - s[24] == 46
    && (s[22] ^ s[32]) == 26
    && s[4] * s[44] == 0xA0
    && s[27] * s[38] == 94
    && s[15] - s[40] == 0xC8
    && (s[53] ^ s[49]) == 86
    && (s[45] ^ s[26]) == 43
    && (s[9] ^ s[54]) == 25
    && s[28] - s[47] == 26
    && s[19] + s[50] == 0xA1
    && s[57] + s[37] == 86
    && (s[18] ^ s[29]) == 56
    && (s[60] ^ s[44]) == 9
    && s[38] * s[15] == 121
    && (s[30] ^ s[37]) == 93
    && s[32] * s[2] == 92
    && s[18] * s[10] == 57
    && s[29] == s[21]
    && s[21] * s[35] == 47
    && s[37] * s[8] == 0xAB
    && s[26] + s[39] == 0x93
    && (s[34] ^ s[26]) == 115
    && (s[31] ^ s[20]) == 64
    && s[16] + s[25] == 0xA9
    && (s[59] ^ s[39]) == 21
    && s[59] + s[0] == 105
    && s[46] + s[34] == 0xA5
    && (s[52] ^ s[30]) == 55
    && s[28] * s[0] == 8
    && s[34] - s[56] == 0xC5
    && s[60] + s[18] == 0xE4
    && (s[40] ^ s[35]) == 110
    && s[16] * s[56] == 0xAC
    && s[54] - s[47] == 13
    && s[55] + s[30] == 0x9C
    && s[33] + s[6] == 0xD4
    && s[29] * s[7] == 0xED
    && (s[29] ^ s[56]) == 56
    && s[37] * s[1] == 100
    && (s[58] ^ s[56]) == 70
    && s[19] * s[2] == 38
    && (s[22] ^ s[26]) == 43
    && s[7] + s[1] == 0x87
    && (s[0] ^ s[27]) == 42
    && s[21] - s[1] == 11
    && s[54] + s[27] == 0xCE
    && (s[13] ^ s[17]) == 59
    && s[19] - s[58] == 18
    && s[17] == s[10]
    && s[14] - s[58] == 77
    && s[52] * s[42] == 78
    && s[50] == s[32]
    && (s[51] ^ s[47]) == 56
    && s[25] + s[38] == 0x94
    && s[52] + s[41] == 0xCF
    && s[44] == s[20]
    && s[25] + s[12] == 102
    && s[36] + s[60] == 0xF1
    && s[41] - s[21] == 17
    && s[36] - s[49] == 68
    && s[9] - s[35] == 68
    && (s[51] ^ s[53]) == 1
    && (s[57] ^ s[34]) == 13
    && s[11] - s[28] == 0xEB
    && s[24] + s[23] == 0x99
    && s[13] + s[24] == 0x95
    && s[12] - s[0] == 0xE9
    && s[31] + s[34] == 96
    && s[53] + s[5] == 0x96
    && s[42] * s[49] == 96
    && s[21] * s[48] == 20
    && s[27] - s[52] == 3
    && s[20] + s[57] == 0x95
    && s[53] * s[10] == 0xDA
    && s[41] + s[1] == 0xC4
    && s[47] - s[1] == 11
    && s[43] == s[19]
    && s[47] + s[39] == 0x93
    && s[58] * s[12] == 81
    && s[26] * s[8] == 65
    && s[46] - s[31] == 69
    && s[37] + s[7] == 104
    && s[4] + s[36] == 0xBC
    && s[32] + s[31] == 0xA2
    && s[5] + s[25] == 101
    && s[29] * s[43] == 0xED
    && (s[45] ^ s[13]) == 16
    && s[48] - s[12] == 59
    && s[23] - s[8] == 9
    && (s[42] ^ s[7]) == 65
    && s[5] - s[43] == 0xFD
    && (s[18] ^ s[60]) == 26
    && (s[3] ^ s[1]) == 47
    && s[17] - s[39] == 43
    && s[20] + s[8] == 0xD3
    && s[53] * s[11] == 0xD8
    && s[6] + s[27] == 0xD2
    && s[3] + s[5] == 0xAB
    && s[35] - s[47] == 0xD2
    && (s[33] ^ s[16]) == 16 )
  {
    puts("Freedom at last!");
  }
  else
  {
    puts("Lost in the darkness, you'll wander for eternity...");
  }
  return 0;
}
```

Looks like a perfect task for [Z3 Theorem Prover](https://github.com/Z3Prover/z3).
Extracted C code and moved it almost intact to Python:

```python
from z3 import *

s_0  = BitVec('s_0', 8)
s_1  = BitVec('s_1', 8)
s_2  = BitVec('s_2', 8)
s_3  = BitVec('s_3', 8)
s_4  = BitVec('s_4', 8)
s_5  = BitVec('s_5', 8)
s_6  = BitVec('s_6', 8)
s_7  = BitVec('s_7', 8)
s_8  = BitVec('s_8', 8)
s_9  = BitVec('s_9', 8)
s_10 = BitVec('s_10', 8)
s_11 = BitVec('s_11', 8)
s_12 = BitVec('s_12', 8)
s_13 = BitVec('s_13', 8)
s_14 = BitVec('s_14', 8)
s_15 = BitVec('s_15', 8)
s_16 = BitVec('s_16', 8)
s_17 = BitVec('s_17', 8)
s_18 = BitVec('s_18', 8)
s_19 = BitVec('s_19', 8)
s_20 = BitVec('s_20', 8)
s_21 = BitVec('s_21', 8)
s_22 = BitVec('s_22', 8)
s_23 = BitVec('s_23', 8)
s_24 = BitVec('s_24', 8)
s_25 = BitVec('s_25', 8)
s_26 = BitVec('s_26', 8)
s_27 = BitVec('s_27', 8)
s_28 = BitVec('s_28', 8)
s_29 = BitVec('s_29', 8)
s_30 = BitVec('s_30', 8)
s_31 = BitVec('s_31', 8)
s_32 = BitVec('s_32', 8)
s_33 = BitVec('s_33', 8)
s_34 = BitVec('s_34', 8)
s_35 = BitVec('s_35', 8)
s_36 = BitVec('s_36', 8)
s_37 = BitVec('s_37', 8)
s_38 = BitVec('s_38', 8)
s_39 = BitVec('s_39', 8)
s_40 = BitVec('s_40', 8)
s_41 = BitVec('s_41', 8)
s_42 = BitVec('s_42', 8)
s_43 = BitVec('s_43', 8)
s_44 = BitVec('s_44', 8)
s_45 = BitVec('s_45', 8)
s_46 = BitVec('s_46', 8)
s_47 = BitVec('s_47', 8)
s_48 = BitVec('s_48', 8)
s_49 = BitVec('s_49', 8)
s_50 = BitVec('s_50', 8)
s_51 = BitVec('s_51', 8)
s_52 = BitVec('s_52', 8)
s_53 = BitVec('s_53', 8)
s_54 = BitVec('s_54', 8)
s_55 = BitVec('s_55', 8)
s_56 = BitVec('s_56', 8)
s_57 = BitVec('s_57', 8)
s_58 = BitVec('s_58', 8)
s_59 = BitVec('s_59', 8)
s_60 = BitVec('s_60', 8)

s = Solver()

s.add(s_48 * s_21 == 20)
s.add(s_32 - s_36 == 0xFA)
s.add(s_37 - s_26 == 0xD6)
s.add(s_16 - s_48 == 8)
s.add(s_55 - s_8 == 0xD5)
s.add(s_7 * s_26 == 0xED)
s.add(s_24 * s_4 == 0xC8)
s.add((s_28 ^ s_34) == 85)
s.add(s_30 - s_55 == 52)
s.add(s_50 + s_59 == 0x8F)
s.add(s_27 + s_44 == 0xD6)
s.add((s_14 ^ s_17) == 49)
s.add(s_20 * s_56 == 0xAC)
s.add(s_58 - s_26 == 0xC2)
s.add((s_6 ^ s_26) == 47)
s.add((s_39 ^ s_14) == 90)
s.add((s_39 ^ s_44) == 64)
s.add(s_40 == s_26)
s.add(s_49 + s_23 == 0x98)
s.add(s_59 * s_23 == 104)
s.add(s_1 - s_28 == 0xDB)
s.add(s_24 - s_29 == 0xD2)
s.add(s_38 - s_24 == 46)
s.add((s_22 ^ s_32) == 26)
s.add(s_4 * s_44 == 0xA0)
s.add(s_27 * s_38 == 94)
s.add(s_15 - s_40 == 0xC8)
s.add((s_53 ^ s_49) == 86)
s.add((s_45 ^ s_26) == 43)
s.add((s_9 ^ s_54) == 25)
s.add(s_28 - s_47 == 26)
s.add(s_19 + s_50 == 0xA1)
s.add(s_57 + s_37 == 86)
s.add((s_18 ^ s_29) == 56)
s.add((s_60 ^ s_44) == 9)
s.add(s_38 * s_15 == 121)
s.add((s_30 ^ s_37) == 93)
s.add(s_32 * s_2 == 92)
s.add(s_18 * s_10 == 57)
s.add(s_29 == s_21)
s.add(s_21 * s_35 == 47)
s.add(s_37 * s_8 == 0xAB)
s.add(s_26 + s_39 == 0x93)
s.add((s_34 ^ s_26) == 115)
s.add((s_31 ^ s_20) == 64)
s.add(s_16 + s_25 == 0xA9)
s.add((s_59 ^ s_39) == 21)
s.add(s_59 + s_0 == 105)
s.add(s_46 + s_34 == 0xA5)
s.add((s_52 ^ s_30) == 55)
s.add(s_28 * s_0 == 8)
s.add(s_34 - s_56 == 0xC5)
s.add(s_60 + s_18 == 0xE4)
s.add((s_40 ^ s_35) == 110)
s.add(s_16 * s_56 == 0xAC)
s.add(s_54 - s_47 == 13)
s.add(s_55 + s_30 == 0x9C)
s.add(s_33 + s_6 == 0xD4)
s.add(s_29 * s_7 == 0xED)
s.add((s_29 ^ s_56) == 56)
s.add(s_37 * s_1 == 100)
s.add((s_58 ^ s_56) == 70)
s.add(s_19 * s_2 == 38)
s.add((s_22 ^ s_26) == 43)
s.add(s_7 + s_1 == 0x87)
s.add((s_0 ^ s_27) == 42)
s.add(s_21 - s_1 == 11)
s.add(s_54 + s_27 == 0xCE)
s.add((s_13 ^ s_17) == 59)
s.add(s_19 - s_58 == 18)
s.add(s_17 == s_10)
s.add(s_14 - s_58 == 77)
s.add(s_52 * s_42 == 78)
s.add(s_50 == s_32)
s.add((s_51 ^ s_47) == 56)
s.add(s_25 + s_38 == 0x94)
s.add(s_52 + s_41 == 0xCF)
s.add(s_44 == s_20)
s.add(s_25 + s_12 == 102)
s.add(s_36 + s_60 == 0xF1)
s.add(s_41 - s_21 == 17)
s.add(s_36 - s_49 == 68)
s.add(s_9 - s_35 == 68)
s.add((s_51 ^ s_53) == 1)
s.add((s_57 ^ s_34) == 13)
s.add(s_11 - s_28 == 0xEB)
s.add(s_24 + s_23 == 0x99)
s.add(s_13 + s_24 == 0x95)
s.add(s_12 - s_0 == 0xE9)
s.add(s_31 + s_34 == 96)
s.add(s_53 + s_5 == 0x96)
s.add(s_42 * s_49 == 96)
s.add(s_21 * s_48 == 20)
s.add(s_27 - s_52 == 3)
s.add(s_20 + s_57 == 0x95)
s.add(s_53 * s_10 == 0xDA)
s.add(s_41 + s_1 == 0xC4)
s.add(s_47 - s_1 == 11)
s.add(s_43 == s_19)
s.add(s_47 + s_39 == 0x93)
s.add(s_58 * s_12 == 81)
s.add(s_26 * s_8 == 65)
s.add(s_46 - s_31 == 69)
s.add(s_37 + s_7 == 104)
s.add(s_4 + s_36 == 0xBC)
s.add(s_32 + s_31 == 0xA2)
s.add(s_5 + s_25 == 101)
s.add(s_29 * s_43 == 0xED)
s.add((s_45 ^ s_13) == 16)
s.add(s_48 - s_12 == 59)
s.add(s_23 - s_8 == 9)
s.add((s_42 ^ s_7) == 65)
s.add(s_5 - s_43 == 0xFD)
s.add((s_18 ^ s_60) == 26)
s.add((s_3 ^ s_1) == 47)
s.add(s_17 - s_39 == 43)
s.add(s_20 + s_8 == 0xD3)
s.add(s_53 * s_11 == 0xD8)
s.add(s_6 + s_27 == 0xD2)
s.add(s_3 + s_5 == 0xAB)
s.add(s_35 - s_47 == 0xD2)
s.add(s_33 ^ s_16 == 16)

print(s.check())
print(s.model())
```

Output:

```text
s_0  = 72,
s_1  = 84,
s_2  = 66,
s_3  = 123,
s_4  = 72,
s_5  = 48,
s_6  = 112,
s_7  = 51,
s_8  = 95,
s_9  = 117,
s_10 = 95,
s_11 = 100,
s_12 = 49,
s_13 = 100,
s_14 = 110,
s_15 = 39,
s_16 = 116,
s_17 = 95,
s_18 = 103,
s_19 = 51,
s_20 = 116,
s_21 = 95,
s_22 = 116,
s_23 = 104,
s_24 = 49,
s_25 = 53,
s_26 = 95,
s_27 = 98,
s_28 = 121,
s_29 = 95,
s_30 = 104,
s_31 = 52,
s_32 = 110,
s_33 = 100,
s_34 = 44,
s_35 = 49,
s_36 = 116,
s_37 = 53,
s_38 = 95,
s_39 = 52,
s_40 = 95,
s_41 = 112,
s_42 = 114,
s_43 = 51,
s_44 = 116,
s_45 = 116,
s_46 = 121,
s_47 = 95,
s_48 = 108,
s_49 = 48,
s_50 = 110
s_51 = 103,
s_52 = 95,
s_53 = 102,
s_54 = 108,
s_55 = 52,
s_56 = 103,
s_57 = 33,
s_58 = 33,
s_59 = 33,
s_60 = 125
```

Convert these ASCII codes to readable text using CyberChef and get the flag:
> HTB{H0p3_u_d1dn't_g3t_th15_by_h4nd,1t5_4_pr3tty_l0ng_fl4g!!!}
