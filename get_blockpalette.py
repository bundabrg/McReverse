import sys

import frida

# Attach to Session Server using USB
try:
    process = frida.get_usb_device().attach("com.mojang.minecraftpe")
except frida.InvalidArgumentError as e:
    print("Unable to find frida instance on USB device. Make sure you are connected to your device with")
    print("a USB cable and running fridaserver or fridaserver64 on the device using adb")
    exit(0)
except frida.ProcessNotFoundError as e:
    print("Process not found. Attempting to start")
    pid = frida.get_usb_device().spawn("com.mojang.minecraftpe")
    process = frida.get_usb_device().attach(pid)


def onMessage(message, data):
    if message['type'] == 'send':
        out = open("blockpalette.nbt", "wb")
        out.write(bytes(message['payload']));

        print("Saved to: blockpalette.nbt");

        process.detach()
        exit(0)


script = process.create_script(open("get_blockpalette.js").read())

script.on('message', onMessage)
script.load()

sys.stdin.read()
