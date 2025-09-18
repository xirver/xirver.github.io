---
layout: post
title: "Lets build a Pwnagotchi"
date: 2025-09-18
---

## What we are going to do?
Today we are going to build our personal `Pwnagotchi`.

## What's a Pwnagotchi?

`Pwnagotchi` is a small, AI-powered device designed for Wi-Fi security enthusiasts and penetration testers. It passively scans for Wi-Fi networks, capturing handshake data that can later be used to test the strength of Wi-Fi passwords. The device uses a neural network to optimize its learning and "behavior", often displaying cute emoji-based moods on its e-ink screen depending on its performance.

If you want to learn more about Pwnagotchi, check out the official [website](https://github.com/evilsocket/pwnagotchi/releases).


## What we need?

In order to build the `Pwnagotchi` we will need the following hardware:

- `Raspberry Pi Zero W`
- `MicroSD` (8GB minimum)
- `MicroUSB cord` (That allows data transfer)
- `Power bank/battery` (In our case UPS Lite)
- `Screen` (Its optional, in our case Waveshare 2.13 E-Paper HAT V4)

## Build and Installation

These are the basics components we will need in order to build our `Pwnagotchi`.

<img src="/images/pwnagotchi/1.jpg" alt=""/>

To start, attach the `UPS-Lite` to our `Raspberry Pi Zero W` and screw it securely in place, ensuring a stable power supply for our `Pwnagotchi`.

<img src="/images/pwnagotchi/2.jpg" alt=""/>

Next, attach the `Waveshare 2.13 E-Paper HAT V4` screen by carefully inserting it into the `Raspberry Pi’s GPIO` pins. Lets take our time during the first insertion, as it can be a bit stiff, be careful not to bend the pins.

<img src="/images/pwnagotchi/3.jpg" alt=""/>

Once all the hardware is securely in place, it’s time to move on to the configuration.

## Configuration

With the hardware in place, it’s time to configure our `Pwnagotchi`. Lets start by preparing the `microSD` card. We’ll use `Raspberry Pi Imager` to install the `Pwnagotchi` image onto it.

You can download the latest official version from the [Pwnagotchi](https://github.com/evilsocket/pwnagotchi/releases) main repository.

Unfortunately the version of the screen I got is not yet supported by the latest official release. I found another version that support it at this [Github Page](https://github.com/DrSchottky/pwnagotchi/releases).

Once we have the image:

1. Open `Raspberry Pi Imager`.

2. Select the device as `Raspberry Pi Zero`.

3. For the OS, choose Custom and browse to the downloaded image.

4. Select our `microSD` card as the storage device and start the installation.

<img src="/images/pwnagotchi/4.jpg" alt=""/>

After the image is written, before ejecting the `microSD`, lets create a file named `config.toml` in the root directory and add the following configuration:

```
main.name = "pwnagotchi"
main.lang = "en"
main.whitelist = [
  "EXAMPLE_NETWORK",
  "ANOTHER_EXAMPLE_NETWORK",
  "fo:od:ba:be:fo:od",
  "fo:od:ba"
]

main.plugins.grid.enabled = true
main.plugins.grid.report = true
main.plugins.grid.exclude = [
  "YourHomeNetworkHere"
]

ui.display.enabled = true
ui.display.type = "waveshare_3"
ui.display.color = "black"
```

`Note: Adjust the values according to your setup, including your whitelist networks and display type.`

Now lets insert the `microSD` into the `Raspberry Pi Zero`, then connect the device to our computer via USB. It should appear as `RNDIS/Ethernet Gadget`.

Configure your network adapter with a manual `IPv4` setup:

- IP address: `10.0.0.1`

- Subnet mask: `255.255.255.0`

- Gateway: `leave empty`

- DNS: `8.8.8.8`

Lets reboot the `Raspberry Pi Zero W`. Once it reconnects to the PC, we can verify it’s online by pinging `10.0.0.2`.

`ping 10.0.0.2`

From here, we have several options:

- `Bettercap`: connect to `10.0.0.2` for network sniffing and testing.

- `Web UI`: open `http://10.0.0.2:8080` (default port; configurable in config.toml).

- `SSH`: connect with `ssh pi@10.0.0.2` to directly edit `config.toml` in `/etc/pwnagotchi/` or other files.

Once our personal configuration is complete, lets power on the device and just like that, our `Pwnagotchi` is ready to go!

<img src="/images/pwnagotchi/5.jpg" alt=""/>

