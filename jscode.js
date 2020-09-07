var ptr_block_palette__get_block = Module.findExportByName("libminecraftpe.so", "_ZNK12BlockPalette8getBlockERKj");
var ptr_block_palette__assign_block_runtime_ids = Module.findExportByName("libminecraftpe.so", "_ZN12BlockPalette21assignBlockRuntimeIdsEv");

if (ptr_block_palette__get_block == null) {
    console.log('Could not find symbol for: BlockPalette::getBlock')
    exit(0);
}

Interceptor.attach(ptr_block_palette__get_block, {
    onEnter: function(args) {
        console.log("assign");
    },
    onLeave: function(retval) {
    }
});
