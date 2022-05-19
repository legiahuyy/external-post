---
title: HCMUS-CTF: LostInParis [Forensic]
author: The Archivist
date: 2022-5-19 9:30:00 +1345
---

I only have the exploit script of this challenge as I cannot find the `server.py` and the challenges are closed. So basically, the challenge gives us 665 random numbers and wants us to guess the following one, based on this we can understand this is the Mersenne Twister **with 665** observed outputs.

```python
import random

class MT19937Recover:
    """Reverses the Mersenne Twister based on 624 observed outputs.
    The internal state of a Mersenne Twister can be recovered by observing
    624 generated outputs of it. However, if those are not directly
    observed following a twist, another output is required to restore the
    internal index.
    See also https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode .
    """
    def unshiftRight(self, x, shift):
        res = x
        for i in range(32):
            res = x ^ res >> shift
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for i in range(32):
            res = x ^ (res << shift & mask)
        return res

    def untemper(self, v):
        """ Reverses the tempering which is applied to outputs of MT19937 """

        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xefc60000)
        v = self.unshiftLeft(v, 7, 0x9d2c5680)
        v = self.unshiftRight(v, 11)
        return v

    def go(self, outputs, forward=True):
        """Reverses the Mersenne Twister based on 624 observed values.
        Args:
            outputs (List[int]): list of >= 624 observed outputs from the PRNG.
                However, >= 625 outputs are required to correctly recover
                the internal index.
            forward (bool): Forward internal state until all observed outputs
                are generated.
        Returns:
            Returns a random.Random() object.
        """

        result_state = None

        assert len(outputs) >= 624       # need at least 624 values

        ivals = []
        for i in range(624):
            ivals.append(self.untemper(outputs[i]))

        if len(outputs) >= 625:
            # We have additional outputs and can correctly
            # recover the internal index by bruteforce
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals+[i]), None)
                r = random.Random()
                r.setstate(state)

                if challenge == r.getrandbits(32):
                    result_state = state
                    break
        else:
            # With only 624 outputs we assume they were the first observed 624
            # outputs after a twist -->  we set the internal index to 624.
            result_state = (3, tuple(ivals+[624]), None)

        rand = random.Random()
        rand.setstate(result_state)

        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]

        return rand
```

```python
#!/usr/bin/env python3
from pwn import *
from MT19937 import MT19937Recover

HOST='103.245.250.31'
PORT = 30620
numbers = []

print('a'.encode())
p = remote(HOST, PORT)
def get_all_numbers():
    global p
    p.recvuntil(b'665 random numbers.\n')
    stream = str(p.recvlineS()[:-1])
    stream = stream.split(' ')
    global numbers
    for elem in stream:
        numbers.append(int(elem))
    return numbers

def recover_next_num(numlist):
    mtr = MT19937Recover()
    r2 = mtr.go(numlist)
    next_num = r2.getrandbits(32)
    return next_num

def solve():
    global p
    get_all_numbers()
    next_num = recover_next_num(numbers)
    p.sendlineafter(b'last random number:\n', str(next_num).encode())
    p.interactive()

if __name__ == '__main__':
    solve()
```

