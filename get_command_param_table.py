import sys
import frida

# Attach to Session Server using USB
process = None
try:
    process = frida.get_usb_device().attach("Minecraft")
except frida.InvalidArgumentError as e:
    print("Unable to find frida instance on USB device. Make sure you are connected to your device with")
    print("a USB cable and running fridaserver or fridaserver64 on the device using adb")
    exit(0)
except frida.ProcessNotFoundError as e:
    print("Process not found. Attempting to start")
    pid = frida.get_usb_device().spawn("com.mojang.minecraftpe")
    process = frida.get_usb_device().attach(pid)


def onMessage(message, data):
    print(message)


script = process.create_script(open("get_command_param_table.js").read())

script.on('message', onMessage)
script.load()
sys.stdin.read()
