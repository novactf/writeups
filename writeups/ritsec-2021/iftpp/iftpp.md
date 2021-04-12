# IFTPP

We were given a `.pcapng` file which I promptly opened with Wireshark.
It is very small, with only 73 packets.

Most of the packets are ICMP packets, and some are rather large. Something is up!

Using Wireshark's export HTTP objects, we get a `rfc.txt` file.
In it, there is a protocol description which basically states that inside the ICMP packets there are `proto3` messages.

Instead of generating a handler from the given description I wrote a parser and had to deal with all the unspecified BS they have to offer.
The parser pretty much followed the RFC, with exception to the places where the RFC is not followed by the packets.

There were three key points where the packets didn't follow the RFC:
- Some packets have no checksum.
- The data packet's checksum did not work.
- The decrypted data was not base64.

## Actually solving the challenge

I got `pyshark` out and began dissecting the ICMP packets.
The challenge was all about extracting the payloads and decrypting them.

### Extracting the packets
As I said, I extracted the packets using `pyshark` and the following script.

```py
import pyshark

capture = pyshark.FileCapture(
    input_file="iftpp_challenge.pcap",
    keep_packets=True,
    display_filter="icmp",
)

parsed_messages = []
for packet in capture:
    pkt = unhexlify(packet.icmp.data)
    msg = Msg.parse_packet(pkt)
    print(msg)
    parsed_messages.append(msg)
```

The parser is long so, instead of pasting it here, you can see it in [`iftpp.py`](iftpp-src/iftpp.py).

### Decrypting the message

Here was where problems came out, while the key process was followed,
the encryption description did not match.
Instead of returning a base64 encoded string it returned the plaintext file.

The encryption/decryption function I wrote was:

```py
def xor_crypt(payload: bytes, key: bytes) -> bytes:
    res = []
    for i in range(len(payload)):
        res.append(payload[i] ^ key[i % len(key)])
    return bytes(res)
```

### Finishing up

Putting it all together, the steps were:
- Extract and read the RFC.
- Implement a way to extract the messages.
- Extract and calculate the shared key.
- Decrypt the message.
- Get the flag.