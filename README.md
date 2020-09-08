# McReverse Tools

This just holds useful tools for use with reversing Minecraft Bedrock. Presently the only
tool is a method of retrieving the block palette with open source tools.

## get_blockpalette

Retrieve a block palette from a Bedrock Client. Presently only tested against a rooted Android client
and makes use of Frida to provide the hooking.

### Quick Start
1. Install requirements. `pip install -r requirements.txt`. Ideally in a virtualenv. Python3 of course.
1. `adb push` a copy of [frida_server](https://github.com/frida/frida/releases) to your device. You may need to
put it in /sdcard
1. `adb shell` in, su to root and copy it to an executable patition. I use /data. IE. `copy /sdcard/frida_server64 /data`. Don't
forget to `chmod +x` it.
1. Run `frida_server64` on the device. You can add `&` to background the task if you want to quit your adb shell.
1. Test that it is reachable. On the PC type `frida-ps -U` which queries running processes over the USB cable.
1. Start minecraft and leave it at the main menu
1. `python get_blockpalette.py` to start the script. It should say its waiting for a block palette.
1. Start a new single player game or load an existing one. It should catch the generated palette and save it uncompressed to `blockpalette.nbt`.
1. Ctrl-C out. You are done.
  
