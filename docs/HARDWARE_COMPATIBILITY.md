# Hardware dependency matrix

Status: **Planned**. No SUMT hardware feature has been validated yet, because the Android phase has not started. Each row moves to *Validated* only with a dated test log on real hardware.

| Hardware | USB VID:PID | Used by | Android API | Validation status |
|---|---|---|---|---|
| CH340 / CH341 USB-TTL | 1A86:7523, 1A86:5523 | UART recovery, ESP32 flash, IR via ESP32 | USB Host + usb-serial-for-android | Planned |
| CH341A programmer (24/25/93 mode) | 1A86:5512 | SPI/I2C/Microwire, EDID, panel EEPROM, PMIC, TCON | USB Host bulk endpoints | Planned |
| CP2102/CP2104 | 10C4:EA60, EA70, EA71 | UART, ESP32 dev boards | usb-serial | Planned |
| FTDI FT232R/FT2232/FT232H | 0403:6001, 6010, 6011, 6014, 6015 | UART | usb-serial | Planned |
| PL2303 | 067B:2303, 23A3, 23B3, 23C3, 23D3 | UART | usb-serial | Planned |
| ESP32 / ESP32-S3 dev board | via the bridges above, or 303A:1001 (native USB) | ESP32 flash, Wi-Fi scope, IR learn/send, Wi-Fi UART | USB Host / Wi-Fi socket | Planned. Needs SUMT firmware |
| HC-05 / HC-06 | Bluetooth SPP | Wireless UART recovery | BluetoothSocket RFCOMM | Planned |
| Phone IR blaster | — | IR remotes | ConsumerIrManager | Planned (device dependent) |
| USB IR dongle | **model TBD by owner** | IR learn/send | USB Host | Blocked: hardware model needed |
| eMMC ISP bridge | **model TBD by owner** | eMMC ISP programmer | USB Host | Blocked: hardware model + protocol needed |
| USB card reader (eMMC adapter) | Mass storage | eMMC image read | libaums (Apache-2.0) | Planned |
| Android TV with network ADB | TCP 5555 | ADB tools | Socket | Planned |

Minimum Android: API 24 (Android 7.0) is realistic for USB Host, BLE permissions and SAF. Recommended target: API 35/36.
