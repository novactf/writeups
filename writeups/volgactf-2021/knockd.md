---
tags: crypto, mt19937
year: 2021
authors: 2021
---

# knockd

For this challenge we were given a script and a packet capture.
I never got to fully understand what the script did, but luckily that was not needed.

From a high-level view, the script would generate random numbers and use them as ports to connect to.
The values were generated using a [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister),
this was evident from the class `mersenne_rng`.
It is well known that the Mersenne Twister is not secure for cryptographic purposes since,
as soon as we capture 624 values, we can predict all the next values.

Taking a closer look at the script we see:
```py
rng = mersenne_rng(0)
for i in range(625):
    number = rng.get_random_number()
    port1 = (number & (2 ** 32 - 2 ** 16)) >> 16
    port2 = number & (2 ** 16 - 1)
```
Bingo!

## Retrieving the values

For me this was the actual hard part of the challenge.
We need to find the ports in the `.pcap` file, I noticed that we had groups of activity separated by 5 seconds,
made obvious by the `time.sleep(5)` at the end of the script.

From there, I noticed that:
- We only cared for the `SYN` packets.
- Only TCP packets from `192.168.0.105` were relevant.

There were also some duplicates, so we can filter retransmissions out.
I ended up using the following Wireshark filter:

```
ip.src == 192.168.0.105 and tcp.connection.syn and !(tcp.analysis.retransmission or tcp.analysis.fast_retransmission)
```

> Note: we could add `tcp.dstport != 2222` to avoid unnecessary packets showing up.

## Solving

We have the values, however we still need to reconstruct the value and crack the PRNG.

### Reconstructing the values

As we previously saw, the number was split into two parts using:
```py
port1 = (number & (2 ** 32 - 2 ** 16)) >> 16
port2 = number & (2 ** 16 - 1)
```

So we can put it back together with:

```py
def join(a, b):
    return (a << 16) | b
```

### Cracking the Twister

To read the number from the `.pcap` I used `pyshark`, a wrapper around `tshark`.

I read the first two numbers of our group of five.
This is because the group has the following form:

```
random_port -> prng_high
random_port -> prng_low
random_port -> 2222
random_port -> prng_low
random_port -> prng_high
```

You can see we only need the first two.
To crack the Twister I used `mt19937predictor`. I suggest you check their page to know more.

### The final script

In the end our script looks like the following:

```py
import pyshark
from mt19937predictor import MT19937Predictor

FILTER="ip.src == 192.168.0.105 and tcp.connection.syn and !(tcp.analysis.retransmission or tcp.analysis.fast_retransmission)"
cap = pyshark.FileCapture(input_file="/home/jmgd/Documents/volgactf/crypto/knock/knockd.pcap", keep_packets=True, display_filter=FILTER)

def join(a, b):
    return (a << 16) | b

def split(n):
    a = (n & (2 ** 32 - 2 ** 16)) >> 16
    b = n & (2 ** 16 - 1)
    return a, b

try:
    predictor = MT19937Predictor()
    while True:
        p1 = int(cap.next().layers[2].dstport)
        p2 = int(cap.next().layers[2].dstport)
        cap.next()
        cap.next()
        cap.next()
        n = join(p1, p2)
        print(p1, p2, n)
        predictor.setrandbits(n, 32)
except StopIteration:
    _n = predictor.getrandbits(32)
    print(split(_n))
```