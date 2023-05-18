CCSniffer
==

This cli is an interface for Zigbee sniffing firmware. The combination is developed for use with the Zigbee Dongle based on the CC2531 chip. The required firmware is based on the bumblebee project and can be found [here](cc2531-sniffer-firmware)

```
Usage: ccsniffer-rust [OPTIONS]

Options:
  -c, --channel <CHANNEL>            [default: 13]
  -f, --capture-file <CAPTURE_FILE>  [default: capture.pcap]
  -d, --debug                        
  -h, --help                         Print help
  -V, --version                      Print version
```

Permissions
----

**Ubuntu:**

By default the sniffer needs root access to access the usb device. To make it work you can add the following udev rule

'SUBSYSTEM=="usb", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="16a8", GROUP="plugdev", TAG+="uaccess"'

