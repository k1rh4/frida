 /**

# Refer to https://github.com/google/ssl_logger/blob/master/ssl_logger.py
# Origin: https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py
# Author : Fanxs
# 2019-12-16

# Rewrite: k1rh4 (2020-0720)

**/

/**[+] bracktrace... **/
var ThreadDef;
var ThreadObj;
Java.perform(function(){
    ThreadDef = Java.use('java.lang.Thread');
    ThreadObj = ThreadDef.$new();
});
function stackTrace() {
    var STACK_TRACE=true;
    if ( STACK_TRACE == true ){
        var stack = ThreadObj.currentThread().getStackTrace();
        for (var i = 2; i < stack.length; i++) {
            console.log(i + " => " + stack[i].toString());
        }
        console.log("-----------------------------------");
    }
}

Java.perform(function() {
  var preference_class = Java.use('android.app.SharedPreferencesImpl$EditorImpl')
  preference_class.putString.overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
    var message = {};
    console.log('[SharedPreferencesImpl]1', k, '=', v);
    message["function"]   = "SharedPrefernece";
    message["data_key"]   = k;
    message["data_value"] = v;
    console.log('[SharedPreferencesImpl]2', k, '=', v);
    
    send(message);
    return this.putString(k, v);
  }
});
  // native function hook
  // Interceptor.attach(Module.findExportByName("LIB_NAME","Java_com_deva...ROOT_CHeckopen"),{
  //   onEnter: function(args){
  //     console.log("Inside java_com d....checkopen");
  //     return 0;

  //   },
  //   onLeave: function(retval)
  //   {
  //     retval.repalce(0);
  //     console.log("Inside onLeave");
  //   }
  // });

// dlopen Hooking
Interceptor.attach(Module.findExportByName(null, "dlopen"),{
  onEnter: function(args){
    this.arg0 = Memory.readUtf8String(args[0]);
    console.log(args[0])
    var message = {}
    message["function"] = "dlopen";
    message["lib_name"] = args[0];
    console.log(message["lib_name"]);
    //send(message, Memory.readByteArray(this.arg0, retval));
    //send(message)
    // if(this.arg0.indexOf("linengine.so")!==-1)
    // {
    //   Thread.sleep(1);
    // }
  },
  onLeave: function(retval)
  {
    return 0;
  }
});