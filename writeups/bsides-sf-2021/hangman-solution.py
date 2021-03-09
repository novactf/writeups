from os import name
from mt19937predictor import MT19937Predictor

first_names = []
with open("first-names.txt", "r") as first:
    for line in first:
        first_names.append(line.strip())

last_names = []
with open("last-names.txt", "r") as last:
    for line in last:
        last_names.append(line.strip())

words = []
with open("words.txt", "r") as w:
    for line in w:
        words.append(line.strip())


def parse_players(data):
    players = []
    for line in data:
        op1, op2 = list(map(lambda s: s.strip(), line.split("-vs-")))
        players.append(op1)
        players.append(op2)
    return players


def parse_last(data):
    _, player = data.strip().split("-vs-")
    return player.strip()[:-1]


def setup_predictor(players):
    # setup the predictor
    predictor = MT19937Predictor()
    # for player in players:
    for i in range(624):
        player = players[i]
        first, last = player.split(" ")
        f = first_names.index(first)
        l = last_names.index(last)
        out = (l << 16) | f
        # print(out)
        predictor.setrandbits(out, 32)
    return predictor


def check_matches(predictor, players):
    # keep feeding
    for i in range(624, len(players)):
        n = predictor.getrandbits(32)
        f = n & 0xFFFF
        l = n >> 16
        # print(f, l)
        p = f"{first_names[f]} {last_names[l]}"
        pp = players[i]
        # print(i, p, pp)
        assert p == pp


from pwn import *

r = remote("hangman-battle-royale-2d147e0d.challenges.bsidessf.net", 2121)
r.recvuntil("prize!\n\n")
r.sendline("10")
r.recvuntil("match-ups are:\n\n")
opponents = r.recvuntil("\n\n").strip().split(b"\n")
players = parse_players(map(lambda b: b.decode(), opponents))
r.recvuntil("\n\n")

last_match = r.recvuntil("\n\n")
players.append(parse_last(last_match.decode()))

r.recvuntil("GOOD LUCK!!\n\n").split(b"\n")

predictor = setup_predictor(players)
check_matches(predictor, players)

s = 1022
for rounds in range(10):
    w = predictor.getrandbits(32) % len(words)
    print(rounds, words[w])
    s = s // 2
    for _ in range(s):
        predictor.getrandbits(64)


r.interactive()
