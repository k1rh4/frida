var Color = {
	    RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
	    Light: {
		            Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
		        }
};


// Script Inspired by https://github.com/0xdea/frida-scripts/tree/master/android-snippets
var LOG = function (input, kwargs) {
    kwargs = kwargs || {};
    var logLevel = kwargs['l'] || 'log', colorPrefix = '\x1b[3', colorSuffix = 'm';
    if (typeof input === 'object')
        input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
    if (kwargs['c'])
        input = colorPrefix + kwargs['c'] + colorSuffix + input + Color.RESET;
    console[logLevel](input);
};

var printBacktrace = function () {
    Java.perform(function() {
        var android_util_Log = Java.use('android.util.Log'), java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        LOG(android_util_Log.getStackTraceString(java_lang_Exception.$new()), { c: Color.Gray });
    });
};

function traceClass(targetClass) {
    var hook;
    try {
        hook = Java.use(targetClass);
		try{
		var exists = hook.exists.clone({ traps: 'all' });}
		catch(e){
		}

    } catch (e) {
        console.error("trace class failed", e);
        return;
    }

    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();

    var parsedMethods = [];
    methods.forEach(function (method) {
        var methodStr = method.toString();
        var methodReplace = methodStr.replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1];
	    //if ( methodReplace.search("loadLibrary") > 0 ) {
         	parsedMethods.push(methodReplace);
	    //	console.log("[DEBUG]" + methodReplace);
	    //}
    });

    uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
        traceMethod(targetClass + '.' + targetMethod);
    });
}

function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1)
        return;

    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    LOG({ tracing: targetClassMethod, overloaded: overloadCount }, { c: Color.Green });

    for (var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function () {
            var log = { '#': targetClassMethod, args: [] };

            for (var j = 0; j < arguments.length; j++) {
                var arg = arguments[j];
                // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                if (j === 0 && arguments[j]) {
                    if (arguments[j].toString() === '[object Object]') {
                        var s = [];
                        for (var k = 0, l = arguments[j].length; k < l; k++) {
                            s.push(arguments[j][k]);
                        }
                        arg = s.join('');
                    }
                }
                log.args.push({ i: j, o: arg, s: arg ? arg.toString(): 'null'});
            }

            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                log.returns = { val: retval, str: retval ? retval.toString() : null };
            } catch (e) {
                console.error(e);
            }
            LOG(log, { c: Color.Blue });
            return retval;
        }
    }
}

// remove duplicates from array
function uniqBy(array, key) {
    var seen = {};
    return array.filter(function (item) {
        var k = key(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


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
       
        
	console.log("get classes");
	var a = enumAllClasses();
	//console.log(a)
	a.forEach(function(s) {
            if (s){classname_return += JSON.stringify(s) + '\n'}
	});
        sendback = enum_signature + classname_return
	var class_array = sendback.split("\n")
	//console.log(typeof(class_array))
	var i;
	var target_class =[];
	for ( i = 0; i < class_array.length; i++ ){
		if ( class_array[i].search("com.") != -1 ) {
			target_class.push(class_array[i].replace(/\"/g,""))
        }
	}
	console.log("done filtering");
	target_class.forEach(traceClass);
    });
}, 0);
