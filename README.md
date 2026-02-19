# ArgonHash
A program to hash files using Argon2 and encode in a base of user's choice

# Motivation
Suppose you have a system of generating easy-to-remember passwords, like e.g. the password is "ilove\<domainname>", so a password for google.com is "ilovegoogle.com". If someone manages to get access to just 1 or 2 of those, they can identify a pattern, and your entire password system becomes compromised. Or maybe you want to use an amazing video you made as a password, but the website does not accept it. This is where this program comes in. Argon2 is the winner of the Password Hashing Competition, and is designed to be essentially irreversible and VERY expensive to brute-force. With some strong settings, even simple passwords can be transformed into something that takes billions of years to brute-force with all the computing power that has ever existed in the world. This means even if they got all of your passwords, they will never figure out your system.

# Web version
There is now a web version [here](https://anonymous1212144.github.io/ArgonHash/). It have some difference with the executable. Here are some notes:
- Parallelism does not work in most browsers
- You cannot upload large files, also trying to generate multiple in one go also throws memory error
- There is a "maximum output length" field which if you enter any number >0 it will only output that many characters in the "results" box

# Usage instructions
Place the executable in the same folder as all the files you want to input (e.g. `message.txt`), and double-click it. Press Enter to accept defaults. If an error occurs, press Enter to exit.

# Features
- This program takes all the required inputs and passes them through Argon2id version 1.3, then encodes the raw hash using the specified character set (e.g. Base64)
- Can hash any file less than 4 GiB. This means you can even input PNG files, and it will work. If you just want a simple string hashed, put that into a txt file. (The limitation is due to Argon2 only supporting message length up to uint32_t limit)
- Generalized encoding system that can handle any number or type of characters, including words or emojis
- Default values so you do not need to enter everything every time, and a few preset character arrays. This can be activated by pressing Enter without typing anything

# Usage explanation
- "Message" is the simple password or file you want encoded. The default file is `message.txt`
- "Nonce" is a salt, and should be as unique as possible. This is because some people precompute a bunch of common inputs so they can look them up quickly (rainbow table). The salt counters that by altering the output so that the effort is useless. The salt should be secret, but does not need to be, as the goal is simply to make old tables useless and force them to recalculate it. This must be at least 8 bytes in size, and the default file is `nonce.txt`
- "Secret" is another password to alter the output, and is like a key in a cipher, so it should be secret. This is not necessary, so you can leave the file empty if you do not want to use this. The default file is `secret.txt`
- "Associated data" is additional data you can add to alter the output further. This is not necessary, so you can leave the file empty if you do not want to use this. The default file is `data.txt`
- "Encoding character set" is the character set you want the encoding to use. Since the hash outputs raw bytes, you cannot use that normally, but you can encode it to e.g. Base64 so it can be pasted into a password field. The default file is `base94.txt`, which includes every visible, printable ASCII character. The program considers every line a character, so you can encode using words or emojis, but not line breaks (empty lines will be ignored)
- "Tag length" is the number of bytes of the output. Note that after the encoding, the number of characters outputted may be different from this number (e.g. tag length of 32 will result in 64 characters when using base16 (hex) encoding). The default value is `32`
- "Iterations" controls how long the hash takes. The bigger the number, the longer it takes. Note that given the irreversibility of the hash, the attacker has to go through the same thing you do to brute-force your password. So the more time this takes, the more time the attacker needs to check each password they guess. This applies to the next 2 variables as well. The default value is `3`
- "Parallelism" controls how many independent (but synchronizing) computational chains are used. The higher the number, the more threads this takes. The default value is `1`
- "Memory size" controls how much memory the hash uses, in kibibytes (1024 bytes). You need at least 8 KiB for each thread (i.e. 8 × parallelism). The default value is 4096 × parallelism
- "Output file" is the file where the output is written. The default file is `output.txt`

# Compilation instructions
Download the official [Argon2 source](https://github.com/P-H-C/phc-winner-argon2) and put `argonhash.c` into the root folder (i.e. inside the same folder that contains the folder "src"), and then run something like this:

`cl /MT /O2 /I ./include argonhash.c src/core.c src/encoding.c src/argon2.c src/blake2/blake2b.c src/thread.c src/opt.c`
