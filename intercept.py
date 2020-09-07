import sys

import frida


def onMessage(message, data):
    print(message)


# Attach to Session Server using USB
try:
    process = frida.get_usb_device().attach("com.mojang.minecraftpe")
except frida.InvalidArgumentError as e:
    print("Unable to find frida instance on USB device. Make sure you are connected to your device with")
    print("a USB cable and running fridaserver or fridaserver64 on the device using adb")
    exit(0)

script = process.create_script(open("jscode.js").read())

script.on('message', onMessage)
script.load()

sys.stdin.read()
