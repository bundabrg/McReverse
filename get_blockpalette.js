let ptr_block_palette__get_block = Module.getBaseAddress("libminecraftpe.so").add(0x053527bc).sub(0x00100000);

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

function readStdString(ptr) {
    const isTiny = (ptr.readU8() & 1) === 0;
    if (isTiny) {
        return ptr.add(1).readUtf8String();
    }

    return ptr.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

function fnvHash(input) {
	let hash = BigInt("0xcbf29ce484222325");

	for(let i = 0; i < input.length; i++){
		hash *= BigInt("0x100000001b3");
        hash ^= BigInt(input.charCodeAt(i));
        hash &= BigInt("0xFFFFFFFFFFFFFFFF");
	}

	return bigIntToIntArray(BigInt.asIntN(62, hash));
}

function bigIntToIntArray(bigInt) {
    bigInt = BigInt(bigInt);
    let lowInt = Math.floor(Number(bigInt / BigInt(2 ** 32)));
    if (bigInt < 0) {
        lowInt -= 1
    }
    let highInt = Number(bigInt - BigInt(lowInt) * BigInt(2 ** 32));
    return [lowInt, highInt];
}


class Block {
    OFFSET_COMPOUND_TAG = 0x80;
    OFFSET_RUNTIME_ID = 0xa8;

    constructor(ptr) {
        this.ptr = ptr;
    }

    getCompoundTag() {
        return new CompoundTag(this.ptr.add(this.OFFSET_COMPOUND_TAG));
    }

    getRuntimeId() {
        return this.ptr.add(this.OFFSET_RUNTIME_ID).readU16();
    }

    getName() {
        return readStdString(this.getCompoundTag().getFirstChild().getData());
    }

    // getLegacyId: function(block) {
    //     // Return the Block->BlockLegacy::legacyId
    //     return block.add(8).readPointer().readPointer().add(0xd4).readU16();
    // }
}

class BlockPalette {
    OFFSET_FIRST_BLOCK = 0x58;
    OFFSET_LAST_BLOCK = 0x60;

    constructor(ptr) {
        this.ptr = ptr;
    }

    getFirstBlockAddress() {
        return this.ptr.add(this.OFFSET_FIRST_BLOCK).readPointer();
    }

    getLastBlockAddress() {
        return this.ptr.add(this.OFFSET_LAST_BLOCK).readPointer();
    }

}

class CompoundTag {
    OFFSET_DATA = 0x8;
    OFFSET_DATA_END = 0x10;
    OFFSET_NAME = 0x20;
    OFFSET_CHILD = 0x38;

    OFFSET_FN_GETID = 0x8 * 6;

    constructor(ptr) {
        this.ptr = ptr;
    }

    getFirstChild() {
        return new CompoundTag(this.getData().readPointer().add(this.OFFSET_CHILD));
    }

    getData() {
        return this.ptr.add(this.OFFSET_DATA);
    }


    // Serialize Tag into buf
    serialize(buf) {
        // Get type of CompoundTag
        let id = this.getId();

        switch (id) {
            case 0x1: // BYTE
                DataOutput.writeByte(buf, this.ptr.add(this.OFFSET_DATA).readU8());
                break;
            case 0x3: // INTEGER
                DataOutput.writeInt(buf, this.ptr.add(this.OFFSET_DATA).readInt());
                break;
            case 0x8: // STRING
                DataOutput.writeUTF(buf, readStdString(this.ptr.add(this.OFFSET_DATA)));
                break;

            case 0xa: // COMPOUND_TAG
                let current = this.ptr.add(this.OFFSET_DATA).readPointer();
                let last = this.ptr.add(this.OFFSET_DATA_END);

                if (!current.equals(last)) {
                    while (true) {
                        let name = readStdString(current.add(this.OFFSET_NAME));
                        let child = new CompoundTag(current.add(this.OFFSET_CHILD));

                        DataOutput.writeByte(buf, child.getId());
                        DataOutput.writeUTF(buf, name);
                        child.serialize(buf);

                        if (current.equals(last.readPointer())) {
                            break;
                        }

                        current = current.add(0x10).readPointer();

                    }
                }
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
        this.palette = args[0];
    },
    onLeave: function (args) {
        console.log("Found a generated BlockPalette. Please wait.");
        interceptor.detach();

        let palette = new BlockPalette(this.palette);

        let current_block_addr = palette.getFirstBlockAddress();
        let last_block_addr = palette.getLastBlockAddress();
        let buf = [];

        let count = 0;
        while (!current_block_addr.equals(last_block_addr)) {
            let block = new Block(current_block_addr.readPointer());

            console.log("Name: " + block.getName());
            // Store it inside a "block" compound tag

            // console.log("Found " + block.getName() + " with id " + block.getRuntimeId());

            let hash = fnvHash(block.getName());
            DataOutput.writeByte(buf, 0x4);
            DataOutput.writeUTF(buf, "name_hash");
            DataOutput.writeInt(buf, hash[0]);
            DataOutput.writeInt(buf, hash[1]);
            DataOutput.writeByte(buf, 0x3);
            DataOutput.writeUTF(buf, "version");
            DataOutput.writeInt(buf, 17959425);
            block.getCompoundTag().serialize(buf);

            // Add Legacy ID - Probably not needed anymore
            // DataOutput.writeByte(buf, 0x3);
            // DataOutput.writeUTF(buf, "id");
            // DataOutput.writeInt(buf, Block.getLegacyId(block.readPointer()));

            current_block_addr = current_block_addr.add(0x8);
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


console.log("Hooked into process. Please start a new single player game.");