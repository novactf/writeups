---
tags: crypto
year: 2021
authors: crit
---
# Hangman Battle Royale

> Can you win at least 8 rounds of Hangman?

We solved this challenge in the last hours of the CTF,
after originally discarding it because it was written in Ruby.
We picked it up because we were hinted that Ruby uses MT19937 as its default PRNG.

## TL;DR

- Feed the MT19937 predictor
- Keep generating numbers accordingly and predict the words
- Win the tournament

## Feeding the predictor

Before playing the challenge printed all matches,
the opponents were first generated using the following method:

```rb
def get_opponents(count)
  return 0.upto(count-1).map do ||
    i = rand(0xFFFFFFFF)
    "#{ FIRST_NAMES[i & 0xFFFF] } #{ LAST_NAMES[i >> 16] }"
  end
end
```

So the number was split into two parts,
through the number list we could reassemble the number and feed the predictor:

```py
def setup_predictor(players):
    predictor = MT19937Predictor()
    for i in range(624):
        player = players[i]
        first, last = player.split(" ")
        f = first_names.index(first)
        l = last_names.index(last)
        out = (l << 16) | f
        # print(out)
        predictor.setrandbits(out, 32)
    return predictor
```

> Note: We used 624 as it is the required number of inputs for the predictor.
> To get all numbers we used 10 rounds.

## Generating the remaining numbers

After feeding the predictor, we need to make sure that it stays up-to-date with the server-side one.
We had more than 624 players, so we used the remaining ones to both keep the predictor up-to-date and check that everything was running smoothly.

Only thing we need now is to generate the word and the list of players that lost.
The word is simple enough, by guessing we did:

```py
w = predictor.getrandbits(32) % len(words)
```

First we tried `predictor.choice`, but that didn't work out.

All that is left now is predicting the players that lose.
That took more than expected because we were calling `getrandbits(32)`,
oblivious to the fact that Ruby floats are 64-bit.
After finding out that detail, everything was working fine.

```py
s = 1022
for rounds in range(10):
    w = predictor.getrandbits(32) % len(words)
    print(rounds, words[w])
    s = s // 2
    for _ in range(s):
        predictor.getrandbits(64)
```

## Winning the tournament

Save all the generated words and send them out.
In the end we get the flag.

```
CTF{hooray_mt19937}
```

For this step we used `pwntools.interactive` but that was too time consuming.
We leave as an exercise to the reader the automation of the script.

Full script is available in [here](hangman-solution.py).