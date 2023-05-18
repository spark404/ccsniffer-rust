CCSniffer
==


Permissions
----

Ubuntu:
By default the sniffer needs root access to access the usb device. To make it work you can add the following udev rule

'SUBSYSTEM=="usb", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="16a8", GROUP="plugdev", TAG+="uaccess"'

