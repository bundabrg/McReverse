import sys

import frida

# We assume that frida-server is run on a remote machine with parameter '-l remotes_own_ip' and will attach
# to it from where this is run. This is mainly because I run linux and the app runs in windows only.

# Parameters
remote_ip = sys.argv[1]

# Attach to Session Server using USB
process = None
try:
    device = frida.get_device_manager().add_remote_device(remote_ip)

    process = device.attach("Minecraft.Windows.exe")
except frida.ProcessNotFoundError as e:
    print("Process not found.")
    exit(0)


def onMessage(message, data):
    if message['type'] == 'send':
        with open("blockpalette.nbt", "wb") as out:
            out.write(bytes(message['payload']));

        print("Saved to: blockpalette.nbt");

        process.detach()
        exit(0)


script = process.create_script(open("get_blockpalette.js").read())

script.on('message', onMessage)
script.load()
sys.stdin.read()
