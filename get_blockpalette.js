var ptr_block_palette__get_block = Module.findExportByName("libminecraftpe.so", "_ZNK12BlockPalette8getBlockERKj");
var ptr_block_palette__assign_block_runtime_ids = Module.findExportByName("libminecraftpe.so", "_ZN12BlockPalette21assignBlockRuntimeIdsEv");

var fn_binary_stream__constructor = new NativeFunction(Module.findExportByName("libminecraftpe.so", "_ZN12BinaryStreamC2Ev"),
        'pointer', ['pointer']);

var fn_compound_tag__write = new NativeFunction(Module.findExportByName("libminecraftpe.so", "_ZNK11CompoundTag5writeER11IDataOutput"),
        'int', ['pointer', 'pointer']);;
var fn_compound_tag_variant__get = new NativeFunction(Module.findExportByName("libminecraftpe.so", "_ZNK18CompoundTagVariant3getEv"),
        'pointer', ['pointer']);


if (ptr_block_palette__get_block == null) {
    console.log('Could not find symbol for: BlockPalette::getBlock')
    exit(0);
}

var DataOutput = {
    MSB: 0x80,
    REST: 0x7F,
    MSBALL: ~0x7F,
    INT: Math.pow(2, 31),
    writeByte: function(buf, data) {
        buf.push(data);
    },
    writeVarInt: function(buf, num) {
        offset = 0
        var oldOffset = offset

        while(num >= INT) {
            buf[offset++] = (num & 0xFF) | MSB
            num /= 128
        }
        while(num & MSBALL) {
            buf[offset++] = (num & 0xFF) | MSB
            num >>>= 7
        }
        buf[offset] = num | 0
    },
    writeInt: function(buf, data) {
        this.writeByte(buf,(data & 0xff000000) >> 24);
        this.writeByte(buf,(data & 0xff0000) >> 16);
        this.writeByte(buf,(data & 0xff00) >> 8);
        this.writeByte(buf,(data & 0xff));
    },
    writeUTF: function(buf, str) {
        var length = str == null ? 0 : str.length;

        this.writeByte(buf,(length & 0xff00) >> 8);
        this.writeByte(buf,(length & 0xff));

        for(var i = 0; i < length; i++) {
            this.writeByte(buf, str.charCodeAt(i));
        }
    },
}


var CompoundTag = {
    writeCompoundTag: function(buf, name, tag) {
        var id = this.getId(tag);
        DataOutput.writeByte(buf, id);
        DataOutput.writeUTF(buf, name);

        this.serialize(buf, tag);
    },
    getId: function(compoundTag) {
        // Tag::getId() using its vtable so we get the correct virtual method
        var fn_tag__get_id = new NativeFunction(compoundTag.readPointer().add(0x4 * 6).readPointer(), 'uint', ['pointer']);
        return fn_tag__get_id(compoundTag);
    },
    getName: function(compoundTag) {
        return compoundTag.add(0x4)
    },
    _readStdString: function(ptr) {
        const isTiny = (ptr.readU8() & 1) === 0;
        if (isTiny) {
            return ptr.add(1).readUtf8String();
        }

        return ptr.add(2 * Process.pointerSize).readPointer().readUtf8String();
    },

    serialize: function(buf, tag) {
        var id = this.getId(tag);

        switch(id) {
            case 0x1: // BYTE
                DataOutput.writeByte(buf, tag.add(0x4).readU8());
                break;
            case 0x3: // INTEGER
                DataOutput.writeInt(buf, tag.add(0x4).readInt());
                break;
            case 0x8: // STRING
                DataOutput.writeUTF(buf, this._readStdString(tag.add(0x4)));
                break;

            case 0xa: // COMPOUND_TAG
                var current = tag.add(0x4).readPointer();

                var last = tag.add(0x8);

                while(!current.equals(last)) {
                    var child = fn_compound_tag_variant__get(current.add(0x8*4));
                    var name = this._readStdString(current.add(0x4*4));

                    this.writeCompoundTag(buf, name, child);
                    current = this._next(current);
                }
                DataOutput.writeByte(buf, 0);
                break;
            default:
                console.log("Unknown Tag ID: " + id);
        }
    },
    _next: function(ptr) {
         if ( ptr.add(4).readPointer().toInt32() != 0) {
            var current = ptr.add(4).readPointer();

            while(current.readUInt() != 0) {
                current = current.readPointer();
            }
            return current;
        } else {
            var current = ptr;

            while ( !current.add(8).readPointer().readPointer().equals(current) ) {
                current = current.add(8).readPointer();
            }
            return current.add(8).readPointer();
        }
    }
}

var Block = {
    getLegacyId: function(block) {
        // Return the Block->BlockLegacy::legacyId
        return block.add(8).readPointer().readPointer().add(0xd4).readU16();
    }
}


// Hook Block Palette assigning the runtime ID's and export the palette
Interceptor.attach(ptr_block_palette__assign_block_runtime_ids, {
    onEnter: function(args) {
        console.log("Found a generated BlockPalette. Please wait.");


        var palette = args[0];

        var block = palette.add(0x8*4).sub(0x4).readPointer();
        var last = palette.add(0x8*4).readPointer();
        var buf = [];

        var count = 0;
        while(!block.equals(last)) {
            var compoundTag = block.readPointer().add(0x0c);

            // Store it inside a "block" compound tag
            DataOutput.writeByte(buf, 0xa);
            DataOutput.writeUTF(buf, "block");

            CompoundTag.serialize(buf, compoundTag);

            // Add Legacy ID
            DataOutput.writeByte(buf, 0x3);
            DataOutput.writeUTF(buf, "id");
            DataOutput.writeInt(buf, Block.getLegacyId(block.readPointer()));

            DataOutput.writeByte(buf, 0);

            block = block.add(0x4);
            count+=1;
        }
        console.log("Found " + count + " blocks in Palette");

        // Add Header
        var header = [0x0a, 0, 0, 0x09];;
        DataOutput.writeUTF(header, "blocks");
        DataOutput.writeByte(header, 0x0a); // Type of List (compound)
        DataOutput.writeInt(header, count);

        // Add End Tag
        DataOutput.writeByte(buf, 0);

        send(header.concat(buf));

    },
    onLeave: function(retval) {
    }
});


console.log("Hooked into process. Please start a new single player game.");