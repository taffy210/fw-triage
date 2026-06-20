# fw-triage

A small, dependency-free toolkit for the first ten minutes with an unknown firmware dump. It answers one question fast: is this blob compressed, weakly obfuscated, or properly encrypted, and if it is encrypted, where does the key live?

This is the companion code to the writeup [A Key in the Binary, a Key in the Silicon](https://zero-entry.co.za/posts/firmware-xiongmai-vs-tplink-vigi/), which pulls apart a cheap XiongMai-based IP camera next to a TP-Link VIGI NVR. The post is the story. This is the methodology you can run on your own dumps.

Pure standard-library Python 3. No pip install, no binwalk dependency. It does not replace binwalk, it answers the questions binwalk does not, like "is this AES or is it one byte of XOR pretending to be AES."

## What is not in here

No firmware. The vendor images from the post are not mine to redistribute, and they are not the point. Bring your own dump, for example a SPI flash read off a CH341A with flashrom:

```
flashrom -p ch341a_spi -r dump.bin
```

Don't commit other people's firmware to your fork either.

## The tools

### entropy.py

Sliding-window Shannon entropy. The tell for encryption is a flat line near 8.0 bits per byte with almost no variance. Compression is high too, but lumpy, with dips at block boundaries. This measures both and gives you a verdict.

```
python3 entropy.py rootfs.bin
python3 entropy.py rootfs.bin -w 4096 --csv entropy.csv    # CSV to plot the line
```

In the post, this is the step where the VIGI rootfs read dead flat at 7.99 across 27MB, which is what said "stream cipher, not compression."

### xor_sweep.py

Single-byte XOR sweep. Before you write "strong crypto" in a report, make sure you are not looking at a one-byte XOR. This XORs the blob against all 256 keys and looks for known file magics or a collapse in entropy.

```
python3 xor_sweep.py rootfs.bin
```

In the post, this returned zero hits on the VIGI, which ruled out the lazy answer and pointed at real AES.

### crypto_indicators.py

Strings, filtered for the words that matter: hardware AES engines, SoC families, eFuse and OTP key storage, crypto libraries, and a couple of obfuscation tells. Point it at the kernel image, which is usually left readable and usually gives the game away.

```
python3 crypto_indicators.py kernel.bin
```

In the post, this is where `AESDMA`, `!sstar,infinity-aes` and `read eFuse timeout` showed up, which is how the key path turned out to be hardware-only.

## Suggested workflow

1. `binwalk firmware.bin` to carve the obvious parts (kernel, headers).
2. `entropy.py` on whatever blob is left. Flat and high means encrypted.
3. `xor_sweep.py` on that blob to rule out trivial obfuscation.
4. `crypto_indicators.py` on the kernel to find out which engine and where the key lives.
5. If the key is in an eFuse, accept that static unpack is off the table and plan a live-device pivot instead.

## License

MIT. See LICENSE.
