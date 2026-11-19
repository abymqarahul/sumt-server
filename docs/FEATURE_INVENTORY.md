# SUMT — Feature Inventory (from reference APK analysis)

**Product:** SUMT — Smart Universal Mobile Terminal
**Reference analysed:** the supplied third-party terminal APK v1.2.7 (versionCode 30, minSdk 24, targetSdk 36), used as a *functional reference only*.

**Method:** I parsed the manifest, the activity, service and receiver lists, the USB device filter, the library class namespaces and about 20,700 DEX string constants (UI labels, status messages and error messages) with androguard. I did not copy, decompile into, or carry over any source code, artwork, animation, layout, branding or bundled binary. Every SUMT feature will be re-implemented from public protocol documentation and chip datasheets.

**Confidence legend**
- **V**: Verified. A dedicated activity or class exists, and the string evidence shows a full workflow: connect, read, write and verify messages.
- **P**: Partial. An activity exists, but the evidence covers only some steps, or the feature depends on proprietary data tables.
- **U**: Unverified. Only strings or labels were found, so the real behaviour can't be confirmed without running the reference app on hardware.

> Rule: wherever a feature depends on a proprietary data table in the reference app (TCON "division repair" images, PMIC register tables, Sony/Mi security-region offsets, the 4 MB merged ESP32 firmware), SUMT **does not copy it**. SUMT ships the engine plus an empty, admin-managed resource catalogue. The owner uploads *their own legally obtained* data through the Admin app, and it reaches customers through the backend resource channel (see `backend/docs/API.md` → Resources).

---

## 0. Platform-level capabilities (shared by many tools)

| # | Capability | Evidence | Hardware | Protocol | Android permissions | SUMT implementation | Tests |
|---|---|---|---|---|---|---|---|
| 0.1 | USB-serial driver layer (CH340/CH341, CP210x, FTDI, PL2303) | V: `usb-serial-for-android` namespaces; USB filter VIDs 0x0403 (FTDI), 0x10C4 (CP210x), 0x067B (PL2303), 0x1A86 (QinHeng) | USB-TTL adapter + OTG | CDC/vendor control transfers, 8N1, 9600–921600 baud | USB Host feature, `USB_PERMISSION` intent, `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Open-source `usb-serial-for-android` (MIT) inside a foreground service; attach/detach receiver | Per-chip loopback test at every baud rate; unplug during transfer |
| 0.2 | Bluetooth SPP serial (HC-05/HC-06) | V: `Bluetooth.SerialService`, "Please set your Bluetooth module Baudrate to 460800" | HC-05 module wired to board UART | RFCOMM SPP | `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN` (12+); legacy `BLUETOOTH`/`ADMIN` | RFCOMM socket service | Pair, connect, echo; out-of-range disconnect |
| 0.3 | Wi-Fi UART bridge (ESP32 / Wi-Fi module) | V: `Wi_fi.MainActivity_wi_fi`, "Wi-Fi UART is not connected" | ESP32 running SUMT bridge firmware | TCP socket to the soft-AP | `INTERNET`, `ACCESS/CHANGE_WIFI_STATE`, `ACCESS_NETWORK_STATE` | Coroutine socket client with reconnect | AP join, socket drop, wrong IP |
| 0.4 | Generic serial terminal console | V: `MainActivityUSB`, CTRL+A/CTRL+D/CTRL+E, BREAK INTO U-BOOT | Any of 0.1–0.3 | Raw UART | as above | Shared terminal view used *inside* the recovery tools (the **standalone UART Connection Detail screen is excluded**) | RX flood, long lines, control keys |
| 0.5 | Activation / licensing | V: `ProActivationActivity`, Play `pairip` licence check, Retrofit | Internet | HTTPS | `INTERNET` | Replaced by the SUMT Keystore-bound activation (`backend/`) | See TEST_PLAN |
| 0.6 | Storage/backup folder, FileProvider sharing | V: `FileProvider`, "/sdcard/…_Backup", "Download/…_CH341A" | — | — | SAF (no broad storage permission on 29+) | App-specific storage + Storage Access Framework export; SUMT-named folders | Low storage; denied SAF |

## 1. ADB & Android TV tools — `TvAdbToolsActivity` (V)

| Feature | What it does | Hardware | Protocol | Notes / SUMT requirement |
|---|---|---|---|---|
| Network ADB connect/disconnect | Connects to the TV at `ip:5555`; handles the RSA authorisation prompt | Phone and TV on the same LAN | ADB wire protocol over TCP (CNXN/AUTH/OPEN/WRTE), RSA-2048 auth | Implement the ADB protocol client independently (the AOSP protocol spec is public); keep the RSA key in the Keystore |
| Shell commands | Runs preset and custom shell commands | " | ADB `shell:` service | Preset list is SUMT-authored |
| APK install via ADB | Pushes to `/data/local/tmp/…apk`, then `pm install` | " | ADB `sync:` SEND + shell | Validate the APK zip header before pushing |
| Partition backup (root) | Finds a partition by name, then `dd` to `/sdcard/<backup>/` plus a SHA-256 | Rooted TV | shell `dd`, `sha256sum` | Marked root-only; read-only operation |
| Boot image backup (root) | Reads boot to `boot.img` plus a sha256 | Rooted TV | " | " |
| Reboot to recovery/bootloader | `reboot recovery` / `reboot bootloader` | " | shell | Confirmation dialog |
| Mi/Netflix-related fix | See §6.4 | | | |

## 2. USB serial / UART recovery

| Feature | Activity | Evidence | Workflow | Hardware | Status |
|---|---|---|---|---|---|
| Auto Serial Recovery | `AutoSerialRecoveryActivity` | V: "Interrupting bootloader…", "Bootloader prompt detected", "fastboot output detected, stopped", "recovery was not confirmed" | Opens UART → user powers on the TV → the app sends break keys until a known U-Boot prompt regex matches (Amlogic, MStar, Realtek, MediaTek, Novatek, HiSilicon) → sends the chipset recovery command profile → watches for recovery or fastboot text → stops. **It never claims success without seeing recovery text** | CH340/FTDI/CP210x/PL2303 TTL adapter; TX/RX/GND only | P: the per-SoC command profiles are vendor U-Boot knowledge. SUMT must author its own profiles and validate each one on a real board before enabling it |
| Manual Serial Recovery | `ManualSerialRecoveryActivity` | V: "Tap chipset, then tap an action button" | Chipset picker → buttons (RECOVERY-1..4, UART ON/OFF, Fastboot) send fixed U-Boot commands | same | P: as above |
| Recovery transport selection | `RecoveryTransportActivity` | V | Choose USB-TTL, Bluetooth HC-05, or Wi-Fi bridge for recovery | 0.1–0.3 | V |
| Baud selection | — | V: 115200/460800/921600; "Baud rate deviation %.1f%% is higher than allowed 3%" | Validates divisor error per chip | — | V |
| Boot-log fault analyser | strings | V: "This tool reports possible causes from text patterns only…" | Regex rules over the captured boot log → possible causes (eMMC, AVB/dm-verity, panel init, partition mount) | — | V: rule-based; feeds the SUMT Smart Repair Assistant |
| Amlogic Mi screen rotation | `AmlogicMiScreenRotateActivity` | V: "Firmware compatibility verified", "Rotation buttons remain locked" | UART → U-Boot break → verify firmware → set the env/rotation command | TTL adapter | P: the command set must be validated per model |
| T950X4 one-click repair | strings | P: "Baud rate set to 921600 for T950X4 repair", "backs up factory data first" | UART at 921600 → backup → write firmware → clear user data → boot | TTL or HC-05 at 921600 | U: board-specific; needs its firmware supplied by the owner |
| Firmware upgrade (TCL / USB firmware) | `ServiceMenuActivity` sections | U: "FIRMWARE UPGRADE TCL", "USB FIRMWARE", "UP FIRMWARE" | Likely UART commands that trigger a USB-update boot | TTL | U: document only until validated |

## 3. ESP32 tools

| Feature | Evidence | Workflow | Hardware | Protocol | Status |
|---|---|---|---|---|---|
| ESP32 detection & flashing (`Esp32FlashActivity`) | V: "Opening ESP32 bootloader", "sync failed. Hold BOOT", "Flash MD5 verified" | DTR/RTS reset into ROM loader → SYNC → (stub) → FLASH_BEGIN/DATA/END → SPI_FLASH_MD5 verify → reset | ESP32 dev board (CP2102/CH340 USB) | Espressif serial ROM protocol (public spec), SLIP framing | V. SUMT implements esptool's protocol in Kotlin |
| Built-in firmware | V: 4 MB merged image at offset 0x0 in the reference APK | — | — | — | **Not copied.** SUMT writes its own open ESP32 firmware (Arduino/ESP-IDF): UART bridge, IR TX/RX, Wi-Fi scope. It is bundled, or delivered through the backend resource channel |
| Wi-Fi oscilloscope (`Esp32WifiScopeActivity`) | V: AP "…_Terminal", `192.168.0.1:8080`, RUN/TRIGGER Auto/Rising/Falling/SPEED/CAL | Phone joins the ESP32 soft-AP → TCP stream of ADC samples → waveform view | ESP32; ADC 0–3.3 V **only**, with a divider/protection | SUMT-defined TCP protocol | V (concept). SUMT defines its own protocol and firmware. Safety warning text required |
| I2C radar / scope | V: "Scanning I2C bus 0x01-0x7F", "Radar complete" | Scans I2C addresses (via CH341A or ESP32) | CH341A / ESP32 | I2C | V |
| ESP32 IR send + learn | V: `IR_LEARN:rawdata=`, "point the remote directly at the ESP32 IR receiver" | The ESP32 captures the raw mark/space timings and sends them to the app; the app sends timings back for transmission | ESP32 + IR receiver (TSOP38238) + IR LED driver | SUMT text protocol over USB serial or Wi-Fi | V |
| TV signal / wiring diagrams | V: "ESP32 UART + IR Send + IR Learn Wiring", "CH341A 16-Pin ZIF Wiring Guide" | Static images | — | — | **SUMT redraws all diagrams originally** (vector) |

## 4. CH341A programmer — `SpiI2cProgrammerActivity` (V)

| Mode | Chips | Operations | Safety logic seen | SUMT requirement |
|---|---|---|---|---|
| SPI (25-series) | 25X20/40/80/16/32 (256 KB–4 MB) plus JEDEC auto-detect (GD25, ZB25VQ, P25Q, IS25LQ, FM25Q, PM25, T25S, ACE25, ECT25) | Detect (0x9F), Read, Backup, Erase (with confirmation), Write changed sectors, Verify, Unlock (status reg) | "Chip not supported. Repair blocked", "SPI chip size not recognized. Repair blocked" | CH341A vendor bulk protocol (public: flashrom `ch341a_spi.c` is GPL, so it is used only as protocol documentation; the implementation is clean-room) + JEDEC SFDP table |
| I2C (24Cxx) | 24C02 … 24C512 | Read, Write (page-size aware), Verify; "no chip erase, load FF file" | "No valid EEPROM data… check VCC, SDA/SCL" | CH341 I2C stream commands |
| Microwire (93Cxx) | 93C46/56/66, x8/x16 ORG | Read, Write, Verify | "ORG jumper must match" | Bit-banged via CH341 UIO stream |
| Wiring guide | 16-pin ZIF / SOP8 clip | — | — | Original SUMT diagrams |
| Save/Load BIN | "Download/…_CH341A" | Export / import with SAF | — | SAF picker |

## 5. EEPROM / panel / display

| Feature | Activity | Evidence | Status / SUMT notes |
|---|---|---|---|
| HDMI EDID repair | `HdmiEdidRepairActivity` | V: 24C02 at 0x50, checksum verify and "REPAIR CHECKSUM", template apply, restore original | V. EDID 1.4/CEA-861 parsing (public spec); checksum fix; write + verify |
| Panel EEPROM repair | `PanelEepromRepairActivity` | V: "Compatible panel data detected", "Mirrored panel data updated" | P. Panel profile tables are proprietary, so SUMT uses the engine plus owner-uploaded profiles |
| PMIC I2C (VGH/VGL/VCOM) | `PmicI2cActivity` | V: about 120 PMIC profile identifiers (RT69xx, SM40xx, TPS6517x, SW50xxx…), "Auto detect checking verified PMIC profiles only" | P. Register maps come from datasheets, so each profile must be authored from its datasheet and validated. Only datasheet-verified profiles are enabled |
| Samsung VGH/VGL live + flash editor | `SamsungVghVglLiveActivity`, `SamsungVghVglFlashEditorActivity` | V: "Samsung verified VGH/VGL uses CH341A SPI profiles" | P. Proprietary profile data; same approach |
| 4K / TCON "division" repair | `DivisionRepairActivity` | V: about 150 named repair images (BOE/CSOT/INX/AUO/LG TCONs) with SHA-256 fingerprints; "Multiple profile matches… Repair blocked" | P. **The repair images are third-party data and are not copied.** SUMT ships a fingerprint-match engine. The owner uploads repair packages as `REPAIR_DATA` resources |
| Backlight calculator | `BacklightCalculatorActivity` | V: preview views | V. Simple LED-string calculation tool (series/parallel, current); kept. *Not* the excluded "Resistor Tools" |
| Panel info / set panel / TCON testing | `ServiceMenuActivity` | U: "SET PANEL TO FHD", "TCON TESTING", "SET OUTPUT DISPLAY" | U. Board-specific UART commands; document only until validated |

## 6. Storage / eMMC / firmware

| Feature | Activity | Evidence | Status |
|---|---|---|---|
| eMMC ISP programmer | `EmmcIspProgrammerActivity` | V: "No supported eMMC ISP bridge found", "BIN size does not fit the detected eMMC", "Verification passed" | P: needs a USB eMMC ISP bridge. The bridge protocol is vendor-specific, so a validated bridge model must be chosen with the owner. Card-reader (USB Mass Storage) mode is feasible through libaums |
| eMMC info / ID / status / life usage | `ServiceMenuActivity` "EMMC INFO/ID/STATUS/LIFE USAGE" | P | Via UART U-Boot `mmc info` / EXT_CSD parsing, or the ISP bridge |
| eMMC user-area dump / image browser | `EmmcUserDumpActivity`, `EmmcImageBrowserActivity` | V: GPT/MBR parse, sparse detection, EXT4 browsing, "Extract selected partition" | V: pure file analysis, no hardware |
| Firmware / GPT analyzer | `FirmwareGptAnalyzerActivity` | V: GPT CRC checks, Android boot/sparse/vbmeta/UBI/GZIP/ZIP detection, raw signature scan, MStar/Amlogic text partition maps | V. Becomes the **SUMT Smart Firmware Analyzer** (no hex editor) |
| eMMC RPMB repair | `EmmcRpmbRepairActivity` | P: "SCAN RPMB REPAIR DATA", security-partition transfer | U/P: high risk. Requires an authenticated RPMB key; document only |
| Mi Netflix fix | `MiNetflixFixActivity` | P: "Source dumps are never edited", builds `…Fixed.bin` | P: restores security-partition data **from the same board's own original dump** into a working dump. SUMT must enforce same-board-only (matching eMMC CID/serial) and never transplant keys between devices |
| Sony Netflix/Amazon fix | strings | P: "restores board security data from Original Sony BIN into Working BIN" | P: same restriction as above |
| webOS repair package (PAK extract & edit) | `WebOsRepairPackageActivity` | V: EPK/PAK header scan, ZIP, "RAR: extract on PC", "SAVE MODIFIED PAK COPY" | P: PAK parsing is feasible. Editing must create copies only |
| USB↔eMMC / NAND copy | `ServiceMenuActivity` "EMMC TO USB", "USB TO NAND" | U: likely UART U-Boot `usb`/`mmc`/`nand` commands | U: document only until validated per SoC |

## 7. IR & remotes — `remote.remote_activity` (V)

| Feature | Evidence | Transport | Status |
|---|---|---|---|
| Phone built-in IR blaster | V: `TRANSMIT_IR`, "Inbuilt IR blaster not available on this phone" | `ConsumerIrManager` | V |
| USB IR dongle | V: "USB IR open failed", "USB IR learn timeout" | USB HID/serial IR dongle | P: the dongle model must be identified. Owner to supply hardware |
| ESP32 IR | see §3 | serial / Wi-Fi | V |
| AC Remote Library | V | NEC/RC5/vendor AC protocols | P: AC codes must come from SUMT's own database (IRremoteESP8266 protocol knowledge is LGPL, used as reference only) |
| Universal remote, Generic, Wi-Fi remote | V: "no verified HDMI/USB code" | | V for NEC/RC5/RC6/Samsung/Sony SIRC encoders (public protocol specs) |
| Chinese LED TV, LG LCD, Samsung, Toshiba service remotes | V: service-code strings ("Menu 1147", "Info > Factory", "In.Start" …) | IR | V: SUMT authors its own service-code knowledge base |
| Service menu code library (Micromax, Mitashi, TCL, Sony, Sharp …) | V | text | V: rebuilt as SUMT knowledge base |
| IR learning, saved/learned remotes, "Save IR to button" | V | ESP32 / USB IR | V: Room DB |

## 8. Other diagnostics

| Feature | Evidence | Status |
|---|---|---|
| Boot-log analysis | V (see §2) | V: rule engine |
| Firmware checksum (SHA-256/MD5) | V | V |
| Audio test, memory test, storage test (from the brief) | **Not found** in the reference APK | Not present in the reference. These are SUMT additions only if the owner wants them (phone-side tests are straightforward) |
| SD display test ("SD DISPLAY TEST") | U: label inside the service menu | Part of the excluded *Screen TEST* family, **not implemented** |

## 9. Excluded (present in the reference, NOT in SUMT)

| Excluded feature | Reference activity | Action |
|---|---|---|
| Resistor Tools | `ResistorToolsActivity` | Not implemented |
| Screen TEST | `ScreenTestActivity` | Not implemented |
| DTH Logo Changer | `DthLogoChangerActivity` ("DISPLAY LOGO") | Not implemented |
| Hex Editor | `HexEditorActivity`, `HexBufferActivity` | Not implemented. The firmware analyzer shows structured fields only, never an editable hex view |
| UART Connection Detail | `UartConnectionDetailsActivity` | Not implemented (UART used internally only) |
| YouTube Channel | youtube link | Not implemented |
| About | `About_us` | Not implemented (version shown on the dashboard only) |
| Terms | `Term` | Not implemented |
| Pro Workspace | (proprietary workspace web link) | Not implemented |

See `EXCLUSION_CHECKLIST.md` for the release-audit grep list.
