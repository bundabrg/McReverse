let ptr_command_registry__is_valid = Module.getBaseAddress("libminecraftpe.so").add(0x068EAEA0);
let ptr_command_registry__symbol_to_string = Module.getBaseAddress("libminecraftpe.so").add(0x068F79E4);
let ptr_google_breakpad__fileid__fileid = Module.getBaseAddress("libminecraftpe.so").add(0x04d6cde4);
let ptr_symbol = Memory.alloc(4);
let fn_command_registry__is_valid = new NativeFunction(ptr_command_registry__is_valid, 'bool', ['pointer', 'pointer']);
let fn_command_registry__symbol_to_string = new NativeFunction(ptr_command_registry__symbol_to_string, 'pointer', ['pointer', 'pointer', 'pointer'])

// function readStdString(ptr) {
//     const isTiny = (ptr.readU8() & 1) === 0;
//     if (isTiny) {
//         return ptr.add(1).readUtf8String();
//     }
//
//     return ptr.add(2 * Process.pointerSize).readPointer().readUtf8String();
// }

// let interceptor = Interceptor.attach(ptr_command_registry__is_valid, {
//     onEnter: function (args) {
//         this.ptr = args[0];
//     },
//     onLeave: function (retval) {
//         interceptor.detach();
//
//         for (let i = 0; i < 1; i++) {
//             ptr_symbol.writeInt(i | 0x100000);
//             if(fn_command_registry__is_valid(this.ptr, ptr_symbol) === 0x01) {
//                 let freemem = Memory.alloc(8);
//                 for (let i = 0; i < 400; i++) {
//                     console.log("\n")
//                 }
//                 console.log("hexdump")
//                 console.log(freemem);
//                 console.log(hexdump(ptr(fn_command_registry__symbol_to_string(this.ptr, ptr_symbol, freemem).sub(1).add(2 * Process.pointerSize))));
//                 console.log(hexdump(freemem))
//             }
//         }
//     }
// });

// let interceptor2 = Interceptor.attach(ptr_google_breakpad__fileid__fileid, {
//     onEnter: function (args) {
//         // console.log(ptr_string);
//
//         // this.eps = args[1].readUtf8String() === "eps";
//         // if (this.eps) {
//         console.log(args[1].readUtf8String());
//         console.log(args[0].readPointer());
//         // }
//     },
//     onLeave: function (retval) {
//         if (this.eps) {
//             interceptor2.detach();
//         }
//     },
// });

let freemem = Memory.alloc(8);

let fn_google_breakpad__fileid__fileid = new NativeFunction(ptr_google_breakpad__fileid__fileid, 'pointer', ['pointer', 'pointer']);
for (let i = 0; i < 71; i++) {
    console.log(hexdump(fn_google_breakpad__fileid__fileid(freemem, Module.getBaseAddress("libminecraftpe.so").add(0x0C442C68).add(0x8 * i).readPointer()).sub(1)));
}

// console.log("Hooked into process. Please start a new single player game.");