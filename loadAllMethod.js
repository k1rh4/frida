// Script Inspired by https://github.com/0xdea/frida-scripts/tree/master/android-snippets
function enumAllClasses() {
    var allClasses = [];
    var classes = Java.enumerateLoadedClassesSync();

    classes.forEach(function(aClass) {
        try {
            var className = aClass.replace(/\//g, ".");
        } catch (err) {}
        allClasses.push(className);
    });

    return allClasses;
}

function enumClassLoaders(){
    var allClassLoaders = []
    var classLoaders = Java.enumerateClassLoadersSync()

    classLoaders.forEach(function(cl) {
        allClassLoaders.push(cl);
    });

    return allClassLoaders;
}

function enumDexClasses(apk_path) {
    var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    var DexFile = Java.use("dalvik.system.DexFile");
    var df = DexFile.$new(apk_path);
    var en = df.entries()

    var dexClasses = []
    while(en.hasMoreElements()){
        dexClasses.push(en.nextElement());
    }

    return dexClasses;
}

function findClasses(pattern) {
    var allClasses = enumAllClasses();
    var foundClasses = [];

    allClasses.forEach(function(aClass) {
        try {
            if (aClass.match(pattern)) {
                foundClasses.push(aClass);
            }
        } catch (err) {}
    });

    return foundClasses;
}

function enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();
    hook.$dispose;

    return ownMethods;
}

function enumLibSo(lib_name){
    exports = Module.enumerateExportsSync(lib_name);
    var foundObj = []
    for(i=0; i<exports.length; i++){
        foundObj.push(String(exports[i].name) + " : " + String(exports[i].address))
    }
    return foundObj
}

setTimeout(function() {
    Java.perform(function() {
        var sendback = ''
        var classname_return = ''
        var methods_return = ''
        var enum_signature = '-enumMmMmMmMm-'
       
        
	    // enumerate all methods in a class   
	    var a = enumMethods("android.content.BroadcastReceiver")
	    a.forEach(function(s) { 
            methods_return += String(s) + '\n'
	    });
        sendback = enum_signature + methods_return

        
        send(sendback)
    });
}, 0);
