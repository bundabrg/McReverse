// BlockPalette::getBlock(this, runtimeId)
let ptr_block_palette__get_block = Module.getBaseAddress("Minecraft.Windows.exe").add(0x013423f0).sub(0x00400000);

var DataOutput = {
    MSB: 0x80,
    REST: 0x7F,
    MSBALL: ~0x7F,
    INT: Math.pow(2, 31),
    writeByte: function (buf, data) {
        buf.push(data);
    },
    writeVarInt: function (buf, num) {
        offset = 0
        var oldOffset = offset

        while (num >= INT) {
            buf[offset++] = (num & 0xFF) | MSB
            num /= 128
        }
        while (num & MSBALL) {
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

/*
    std::string format
 */
function readStdString(ptr) {
    const isTiny = (ptr.readU8() & 1) === 0;
    if (isTiny) {
        return ptr.add(1).readUtf8String();
    }

    return ptr.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

/*
  I don't really know what this structure is but found in Windows PE build of Education for strings
  Structure is:
    16 bytes: Data  - Could be a CString or a pointer to a CString
    4 bytes: Length - Length of String
    1 byte: Type  - 0xf if data is a cstring, 0x1f if its a pointer to a cstring
 */
function readWindowsString(ptr) {
    const isTiny = ptr.add(0x14).readU8() === 0xf;
    if (isTiny) {
        return ptr.readUtf8String();
    }

    return ptr.readPointer().readUtf8String();
}


class BlockPalette {
    OFFSET_FIRST_BLOCK = 0x40;
    OFFSET_LAST_BLOCK = 0x44;

    PTR_SIZE = 0x4;

    constructor(ptr) {
        this.ptr = ptr;
    }

    getFirstBlockAddress() {
        return this.ptr.add(this.OFFSET_FIRST_BLOCK).readPointer();
    }

    getLastBlockAddress() {
        return this.ptr.add(this.OFFSET_LAST_BLOCK).readPointer();
    }

    getNextBlock(current_block_ptr) {
        return current_block_ptr.add(this.PTR_SIZE);
    }

}

class Block {
    OFFSET_COMPOUND_TAG = 0x38;
    OFFSET_RUNTIME_ID = 0x44;

    constructor(ptr) {
        this.ptr = ptr;
    }

    getCompoundTag() {
        return new CompoundTag(this.ptr.add(this.OFFSET_COMPOUND_TAG));
    }

    getRuntimeId() {
        return this.ptr.add(this.OFFSET_RUNTIME_ID).readU16();
    }

    // Honestly too hard right now and not needed
    // getName() {
    //     return readStdString(this.getCompoundTag().getFirstChild().getData());
    // }

    // Do we need legacyId anymore?
    // getLegacyId: function(block) {
    //     // Return the Block->BlockLegacy::legacyId
    //     return block.add(8).readPointer().readPointer().add(0xd4).readU16();
    // }
}


class CompoundTag {
    OFFSET_DATA = 0x24;
    OFFSET_NAME = 0x10;
    OFFSET_CHILD = 0x28;

    OFFSET_FN_GETID = 0x4 * 5;

    constructor(ptr) {
        this.ptr = ptr;
    }

    // Serialize Tag into buf
    serialize(buf) {
        // Get type of CompoundTag
        let id = this.getId();

        switch (id) {
            case 0x1: // BYTE
                DataOutput.writeByte(buf, this.ptr.add(0x4).readU8());
                // console.log("Byte: " + this.ptr.add(0x4).readU8());
                break;
            case 0x3: // INTEGER
                DataOutput.writeInt(buf, this.ptr.add(0x4).readInt());
                // console.log("Int: " + this.ptr.add(0x4).readInt());
                break;
            case 0x8: // STRING
                DataOutput.writeUTF(buf, readWindowsString(this.ptr.add(0x4)));
                // console.log("String: " + readWindowsString(this.ptr.add(0x4)));
                break;

            case 0xa: // COMPOUND_TAG
                // These are stored in a Binary Tree for Education
                let self = this;

            function processChild(ptr) {
                // End of line?
                if (ptr.add(0xd).readU8() === 1) {
                    return;
                }

                // Left Branch
                processChild(ptr.readPointer());

                // Ourself
                let name = readWindowsString(ptr.add(self.OFFSET_NAME));
                let child = new CompoundTag(ptr.add(self.OFFSET_CHILD));
                DataOutput.writeByte(buf, child.getId());
                DataOutput.writeUTF(buf, name);
                child.serialize(buf);

                // Right Branch
                processChild(ptr.add(0x8).readPointer());
            }


                let root = this.ptr.add(0x4).readPointer();
                processChild(root.add(0x4).readPointer());

                DataOutput.writeByte(buf, 0);
                break;
            default:
                console.log("Unknown Tag ID: " + id);
        }
    }

    getId() {
        // CompoundTag::getId() using its vtable so we get the correct virtual method
        let fn_compound_tag__get_id = new NativeFunction(this.ptr.readPointer().add(this.OFFSET_FN_GETID).readPointer(), 'uint', ['pointer']);
        return (fn_compound_tag__get_id(this.ptr));
    }
}

// Hook a function that we can access the block palette memory from
let interceptor = Interceptor.attach(ptr_block_palette__get_block, {
    onEnter: function (args) {
        let palette = new BlockPalette(this.context.ecx); // Its a __fastcall so *this is in ecx

        console.log("Found a generated BlockPalette. Please wait.");
        interceptor.detach();

        let current_block_addr = palette.getFirstBlockAddress();
        let last_block_addr = palette.getLastBlockAddress();
        let buf = [];

        let count = 0;
        while (!current_block_addr.equals(last_block_addr)) {
            let block = new Block(current_block_addr.readPointer());

            // Store it inside a "block" compound tag
            DataOutput.writeByte(buf, 0xa);
            DataOutput.writeUTF(buf, "block");

            block.getCompoundTag().serialize(buf);

            // Add Legacy ID - Probably not needed anymore
            // DataOutput.writeByte(buf, 0x3);
            // DataOutput.writeUTF(buf, "id");
            // DataOutput.writeInt(buf, Block.getLegacyId(block.readPointer()));

            DataOutput.writeByte(buf, 0);
            current_block_addr = palette.getNextBlock(current_block_addr);

            count += 1;
        }
        console.log("Found " + count + " blocks in Palette");

        // Add Header
        var header = [0x0a, 0, 0, 0x09];
        DataOutput.writeUTF(header, "blocks");
        DataOutput.writeByte(header, 0x0a); // Type of List (compound)
        DataOutput.writeInt(header, count);

        // Add End Tag
        DataOutput.writeByte(buf, 0);

        send(header.concat(buf));

    },
});


console.log("Hooked into process.");