# Intended Solve
## Description
**Victory, Thy Name is Plankton**

Mr. Krabs is very worried that you have found malware on his computer.  He thinks Plankton might have been using the program to steal the Krabby Patty Secret Formula!

Can you analyze the malware to figure out what commands Plankton sent to Mr. Krabs computer?

## Part 1

For this challenge, we'll be going after the implant, so open up `MoneyGrabber.exe` in Ghidra or your decompiler of choice.

After reverse engineering the file, you'll find that the C2:
- Takes in direct TCP stream data
- Uses a one time pad to derive a key
- Decrypts the TCP stream data using RC4 with the key derived from the OTP

If you do enough reversing, you come out to roughly the following:

```c
unsigned char *decrypt(char *ciphertext, int len){
    char *key = "\xda\x88\x0d\xf4\xf6\xc2\x2b\x10\x2e\x50\x22\x16\x46\x72\x0c";
    char flag[] = "\x85\xe5\x54\xab\x98\xf1\x7c\x4f\x4c\x63\x17\x21\x19\x14\x5e\xeb\xbb\x63\xb0\xd7\xe3\x56";

    for (int i = 0; i < strlen(key); i++) {
        flag[i] ^= key[i % 15];
    }

    unsigned char *plaintext = malloc(len * sizeof(char));
    memset(plaintext, 0, len * sizeof(char));

    RC4(flag, (char *)ciphertext, plaintext, len);

    return plaintext;
}
```

You can retrieve the key with the following python script:

```python
key = b"\xda\x88\x0d\xf4\xf6\xc2\x2b\x10\x2e\x50\x22\x16\x46\x72\x0c"
flag = bytearray(b"\x85\xe5\x54\xab\x98\xf1\x7c\x4f\x4c\x63\x17\x21\x19\x14\x5e\xeb\xbb\x63\xb0\xd7\xe3\x56")

for i in range(len(flag)):
    flag[i] ^= key[i % len(key)]

print(flag.decode())
```
Part of the flag retrieved: `mY_n3W_b357_fR13nD!!}`

## Part 2

The challenge asks us to figure out what Plankton was doing on Mr. Krabs computer.

First, find all of the TCP data that comes from the bad actor's machine in the packet capture (192.168.157.145, seen several times so far).  There are only two TCP streams, and one is the picture download from earlier.

Take the other stream, isolate the data being sent from the bad actor to Mr. Krabs, and save it as raw.  We know the payload is being decrypted using the RC4 algorithm (from reversing the C2) before being used, so we can decrypt it with the following Python script.

```python
KEY = b"_mY_n3W_b357_fR13nD!!}"
CIPHER = ARC4.new(KEY)

with open(sys.argv[1], "rb") as fd:
    obj = CIPHER.encrypt(fd.read())

print(obj)
```

This gets you a C object file which works as a Cobalt strike beacon object file.  You can determine this in any number of ways:

- Reversing the C2 and realizing the object file is loaded directly into program memory and run
- Looking at the decrypted binary and noticing all of the ELF sections in plain text
- Finding any one of the numerous mentions of the word Beacon throughout both the object and C2

Once you have the object, load it into Ghidra.

If you reverse the Beacon Object file correctly, you'll get some variation of the following:

```c
char *key = "\x03\x7b\xfb\xb7\x2d\x22\x72\xeb\x08\x7e\xdf\xe5\x05\x0a\xb5\xd2\x45";
char flag[] = "\x56\x36\xba\xe4\x7e\x59\x10\xd8\x3c\x1d\xef\xab\x76\x55\x81\xa0\x76";

for (int i = 0; i < 18; i++) {
    flag[i] ^= key[i];
}

char result[44];
sprintf(result, "Windows version: %ld.%ld, OS build number: %ld", version_info.dwMajorVersion, version_infodwMinorVersion, version_info.dwBuildNumber);

for (int i = 0; i < 44; i++) {
    result[i] ^= flag[i % 17];
}
````

Another key is being derived and used as a one time pad to encrypt the returned data.  Deriving the key with another Python script gets us the following:

```python
key = b"\x03\x7b\xfb\xb7\x2d\x22\x72\xeb\x08\x7e\xdf\xe5\x05\x0a\xb5\xd2\x45"
flag = bytearray(b"\x56\x36\xba\xe4\x7e\x59\x10\xd8\x3c\x1d\xef\xab\x76\x55\x81\xa0\x76")

for i in range(len(flag)):
    flag[i] ^= key[i % len(key)]

print(flag.decode())
```
Other part of the flag: `UMASS{b34c0Ns_4r3`

Combining the two halves of the flag you get:

```
UMASS{b34c0Ns_4r3_mY_n3W_b357_fR13nD!!}
```
