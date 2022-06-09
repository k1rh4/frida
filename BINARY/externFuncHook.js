var baseAddr = Module.findBaseAddress('Qt5Widgets.dll');
console.log('Qt5Widgets.dll baseAddr: ' + baseAddr);
//var setEnableOffset = 0x1800424c0;
//var setEnable1 = Number(baseAddr) + setEnableOffset; 
//console.log('setEnable1 Addr: '+setEnable1);


// setEnable widget -> edit menu 
const symbolAddr = Module.getExportByName('Qt5Widgets.dll','?setEnabled@QWidget@@QEAAX_N@Z');
console.log('symbol Addr: '+symbolAddr);

Interceptor.attach(symbolAddr, {
    onEnter: function(args){
        //console.log('[+] Called QWidget::setEnabled ['+symbolAddr+']');
        //console.log('[+] args[0] = [' + args[0]+ ']');
        //dumpAddr('args[0]', args[0], 0x16);
        this.context.rdx=0x1
        //console.log(JSON.stringify(this.context,0,2));

        //args[1] = ptr("T12"); // insert integer 
        // args[1] = ptr(Memory.allocUtf8String("AAAAAAA!")); 
        //console.log('[+] args[1] = [' + args[1] + ']');
        //dumpAddr('args[1]', args[1], 0x16);
        
    },

    onLeave: function(retval)
    {
        this.context.eax = 0x0;
        //console.log('context information:');
        //console.log('context: ' + JSON.stringify(this.context));

    }
});

 
// setEnalbedAction menu that is located tab people+ group+ 
const symbolAddr2 = Module.getExportByName('Qt5Widgets.dll','?setEnabled@QAction@@QEAAX_N@Z');
console.log('symbol Addr: '+symbolAddr2);
Interceptor.attach(symbolAddr2, {
    onEnter: function(args){
        this.context.rdx=0x1
        //console.log(JSON.stringify(this.context,0,2));
    },
    onLeave: function(retval)
    {
    }
});


const symbolAddr3 = Module.getExportByName('Qt5Widgets.dll','?permissions@QFileSystemModel@QT@@QEBA?AV?$QFlags@W4Permission@QFileDevice@QT@@@2@AEBVQModelIndex@2@@Z');
console.log('symbol Addr: '+symbolAddr3);
Interceptor.attach(symbolAddr3, {
    onEnter: function(args){
        //this.context.rdx=0x1
        console.log(JSON.stringify(this.context,0,2));
    },
    onLeave: function(retval)
    {

    }
});




function dumpAddr(info, addr, size)
{
    if(addr.isNull()) return;
    console.log('Data dump' + info + ':');
    var buf = Memory.readByteArray(addr, size);
    console.log(hexdump(buf, {offset:0, length: size, header: true, ansi:false }));
}
