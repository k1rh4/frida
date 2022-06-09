from __future__ import print_function

import frida
import sys

def on_message(message, data):
    print("[%s]=> %s "%(message, data))

def main(target_process):
    session = frida.attach(target_process)
    #print([x.name for x in session.enumerate_modules()])
    f = open("hook.js","r")
    script_data = f.read()
    script = session.create_script(script_data)
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented progra \n\n\n");
    sys.stdin.read()
    session.detach()
    f.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("this script needs pid or proc name:)")
        sys.exit(1)

    try:
        target_process =int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)
