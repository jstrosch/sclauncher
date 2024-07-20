# SCLauncher - Shellcode Tester, Debugger and PE-File Wrapper

This program is designed to load 32-bit or 64-bit shellcode and allow for execution or debugging. In addition, it can produce executable PE files based on the desired shellcode. This can ease testing as the output binary can be used by standard reverse engineering tools (i.e. IDA Pro (even free) and debuggers).

<img src="images/help.png">

Release binaries are available. You can view a demo of this tool on [YouTube](https://youtu.be/U8SkM99TB2g)

This program provides several options for working with your shellcode, organized by their usage.

**Global arguments**
- -f: required, path of the file to load shellcode from
- -ep: adjusts the entry point offset. If debugging, this will become the offset that is executed. if using with PE file creation, this will become the *AddressOfEntry* value

**Debugging shellcode**
- -bp: SCLauncher will insert a breakpoint (0xCC) at the desired offset. *Note, this doesn't not appear to work with all debuggers.*
- -pause: Pauses execution before executing the shellcode, allowing for a debugger to be attached or other monitoring tools to be started.
- -d: path to a file to load additional content. For example, if the shellcode is dependent on other content being in memory.
- -mm: Works with -d only, this will load the additional content pointed to by the *-d* argument as a memory mapped file.

**Creating a PE File**
- -pe: Tells SCLauncher to create a PE file
- -d: If used in the context of PE file creation, will create a new section named *.content* with the content of this file.
- -64: Creates a 64-bit executable, for use with 64-bit shellcode.
- -o: Defines outpout file name for generated PE file. Default is *sc_outpout.exe*.

## Executing Shellcode From a File

The only required argument is to provide the path to the file that contains your shellcode. You do that by using the ```-f``` argument. This will be copied into memory and executed. Additionally, you can use the ```-ep``` argument to adjust the entry point by X bytes. This allows for shellcode that does not begin execution at the beginning of the binary blob. Finally, ```-bp``` determines if a breakpoint should be inserted before the shellcode. This will be done through a ```0xCC``` byte, which is an INT3. This allows you to run the program under a debugger, defining the command line arguments as appropriate. Inserting a breakpoint will allow the debugger to interrupt execution before the shellcode is executed. If you are *not* running under a debugger, do not insert a breakpoint as that will cause the program to crash.

<img src="images/shellcode_file.png">

## Producing a PE file

You can use the ```-pe``` argument to produce a PE file that essentially wraps the shellcode. The shellcode is placed in the ```.text``` section. The entry point is defined as the beginning of the section, unless the ```-ep``` argument is used. This argument will define an offset from the beginning of the section and be used to update the PE files entry point (i.e. AddressOfEntry field). Additionally, the ```-64``` argument can be used to generate a 64-bit PE file, likely for 64-bit shellcode. The resulting PE file can be analyzed via common reverse engineering tools such as IDA Pro, Ghidra or a debugger such as x32dbg/WinDbg/etc.

<img src="images/produce_pe.png">

If the *-d* argument is used, SCLauncher will create a new section named *.content* and copy the contents of the file into this section. This section will follow the *.text* section.

<img src="images/additional_content.png">

## What if I have a char array?

If you have shellcode that is not already in a binary state, you can use CyberChef to convert that shellcode and download it as a file. 

<img src="images/char_array.png">

Here is an example of shellcode from [Exploit-DB](https://www.exploit-db.com/exploits/48116) that was converted to binary content on [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=XHg4OVx4ZTVceDgzXHhlY1x4MjBceDMxXHhkYlx4NjRceDhiXHg1Ylx4MzBceDhiXHg1Ylx4MGNceDhiXHg1Ylx4MWNceDhiXHgxYlx4OGJceDFiXHg4Ylx4NDNceDA4XHg4OVx4NDVceGZjXHg4Ylx4NThceDNjXHgwMVx4YzNceDhiXHg1Ylx4NzhceDAxXHhjM1x4OGJceDdiXHgyMFx4MDFceGM3XHg4OVx4N2RceGY4XHg4Ylx4NGJceDI0XHgwMVx4YzFceDg5XHg0ZFx4ZjRceDhiXHg1M1x4MWNceDAxXHhjMlx4ODlceDU1XHhmMFx4OGJceDUzXHgxNFx4ODlceDU1XHhlY1x4ZWJceDMyXHgzMVx4YzBceDhiXHg1NVx4ZWNceDhiXHg3ZFx4ZjhceDhiXHg3NVx4MThceDMxXHhjOVx4ZmNceDhiXHgzY1x4ODdceDAzXHg3ZFx4ZmNceDY2XHg4M1x4YzFceDA4XHhmM1x4YTZceDc0XHgwNVx4NDBceDM5XHhkMFx4NzJceGU0XHg4Ylx4NGRceGY0XHg4Ylx4NTVceGYwXHg2Nlx4OGJceDA0XHg0MVx4OGJceDA0XHg4Mlx4MDNceDQ1XHhmY1x4YzNceGJhXHg3OFx4NzhceDY1XHg2M1x4YzFceGVhXHgwOFx4NTJceDY4XHg1N1x4NjlceDZlXHg0NVx4ODlceDY1XHgxOFx4ZThceGI4XHhmZlx4ZmZceGZmXHgzMVx4YzlceDUxXHg2OFx4MmVceDY1XHg3OFx4NjVceDY4XHg2M1x4NjFceDZjXHg2M1x4ODlceGUzXHg0MVx4NTFceDUzXHhmZlx4ZDBceDMxXHhjOVx4YjlceDAxXHg2NVx4NzNceDczXHhjMVx4ZTlceDA4XHg1MVx4NjhceDUwXHg3Mlx4NmZceDYzXHg2OFx4NDVceDc4XHg2OVx4NzRceDg5XHg2NVx4MThceGU4XHg4N1x4ZmZceGZmXHhmZlx4MzFceGQyXHg1Mlx4ZmZceGQw).


## Compiling From Source

This program is intended to be compiled with the C/C++ compiler from Microsoft. You can use the `Developer Command Prompt` after installing the free/community version to compile using `cl`. An example of this command would be:

```cl sclauncher.c```

This will produce the exectuable ```sclauncher.exe```.
