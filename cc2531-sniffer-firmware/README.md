Firmware
===

This is a modfied copy of the bumblebee firmware.


The firmware is in the ihex format. To convert to a binary (with padding) use the following command:

```
objcopy --gap-fill 0xFF --pad-to 0x040000 \
    -I ihex cc2531-bumblebee-latest.hex \
    -O binary cc2531-bumblebee-latest.bin
```

The binary firmware can be uploaded with a programmer supporting the cc2531 chip. For example [ccloader|http://github.com/spark404/ccloader-rust].

Checksums
---
```
sha256 7d4545dda7c2d9090bff3472aca4892ea98917f4909dbf95fa2328a9aff97438  cc2531-bumblebee-spark404.hex
```

