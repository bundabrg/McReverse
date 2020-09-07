import frida

jscode = """
"""

# Attach to Session Server using USB
process = frida.get_usb_device().attach("com.mojang.minecraftpe")
script = process.create_script(jscode)

script.on('message')