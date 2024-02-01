# SCLauncher - Basic Shellcode Tester, Debugger and PE-File Wrapper

This program is designed to load 32-bit or 64-bit shellcode and allow for execution or debugging. In addition, it can produce executable PE files based on the desired shellcode. This can ease testing as the output binary can be used by standard reverse engineering tools (i.e. IDA Pro (even free) and debuggers).

<img src="images/help.png">

Release binaries are available. You can view a demo of this tool on [YouTube](https://youtu.be/U8SkM99TB2g)

This program provides several options for working with your shellcode:
* You can use the ```-pause``` argument to pause this program before executing the shellcode. This allows for a debugger to be attached and breakpoints to be set. Keep in mind that there are options available to have this utility set breakpoints for you, see the ```-bp``` argument.
* You can produce PE files from your shellcode, then disassemble or debug them as you would a normal PE file.
* You can run the the program directly under a debugger, providing the appropriate arguments through your debuggers interface.

## Executing Shellcode From a File

The only required argument is to provide the path to the file that contains your shellcode. You do that by using the ```-f``` argument. This will be copied into memory and executed. Additionally, you can use the ```-ep``` argument to adjust the entry point by X bytes. This allows for shellcode that does not begin execution at the beginning of the binary blob. Finally, ```-bp``` determines if a breakpoint should be inserted before the shellcode. This will be done through a ```0xCC``` byte, which is an INT3. This allows you to run the program under a debugger, defining the command line arguments as appropriate. Inserting a breakpoint will allow the debugger to interrupt execution before the shellcode is executed. If you are *not* running under a debugger, do not insert a breakpoint as that will cause the program to crash.

<img src="images/shellcode_file.png">

## Producing a PE file

You can use the ```-pe``` argument to produce a PE file that essentially wraps the shellcode. The shellcode is placed in the ```.text``` section. The entry point is defined as the beginning of the section, unless the ```-ep``` argument is used. This argument will define an offset from the beginning of the section and be used to update the PE files entry point (i.e. AddressOfEntry field). Additionally, the ```-64``` argument can be used to generate a 64-bit PE file, likely for 64-bit shellcode. The resulting PE file can be analyzed via common reverse engineering tools such as IDA Pro, Ghidra or a debugger such as x32dbg/WinDbg/etc.

<img src="images/produce_pe.png">

## What if I have a char array?

If you have shellcode that is not already in a binary state, you can use CyberChef to convert that shellcode and download it as a file. 

<img src="images/char_array.png">

Here is an example of shellcode from [Exploit-DB](https://www.exploit-db.com/exploits/48116) that was converted to binary content on [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=XHg0OFx4MzFceGZmXHg0OFx4ZjdceGU3XHg2NVx4NDhceDhiXHg1OFx4NjBceDQ4XHg4Ylx4NWJceDE4XHg0OFx4OGJceDViXHgyMFx4NDhceDhiXHgxYlx4NDhceDhiXHgxYlx4NDhceDhiXHg1Ylx4MjBceDQ5XHg4OVx4ZDhceDhiXHg1Ylx4M2NceDRjXHgwMVx4YzNceDQ4XHgzMVx4YzlceDY2XHg4MVx4YzFceGZmXHg4OFx4NDhceGMxXHhlOVx4MDhceDhiXHgxNFx4MGJceDRjXHgwMVx4YzJceDRkXHgzMVx4ZDJceDQ0XHg4Ylx4NTJceDFjXHg0ZFx4MDFceGMyXHg0ZFx4MzFceGRiXHg0NFx4OGJceDVhXHgyMFx4NGRceDAxXHhjM1x4NGRceDMxXHhlNFx4NDRceDhiXHg2Mlx4MjRceDRkXHgwMVx4YzRceGViXHgzMlx4NWJceDU5XHg0OFx4MzFceGMwXHg0OFx4ODlceGUyXHg1MVx4NDhceDhiXHgwY1x4MjRceDQ4XHgzMVx4ZmZceDQxXHg4Ylx4M2NceDgzXHg0Y1x4MDFceGM3XHg0OFx4ODlceGQ2XHhmM1x4YTZceDc0XHgwNVx4NDhceGZmXHhjMFx4ZWJceGU2XHg1OVx4NjZceDQxXHg4Ylx4MDRceDQ0XHg0MVx4OGJceDA0XHg4Mlx4NGNceDAxXHhjMFx4NTNceGMzXHg0OFx4MzFceGM5XHg4MFx4YzFceDA3XHg0OFx4YjhceDBmXHhhOFx4OTZceDkxXHhiYVx4ODdceDlhXHg5Y1x4NDhceGY3XHhkMFx4NDhceGMxXHhlOFx4MDhceDUwXHg1MVx4ZThceGIwXHhmZlx4ZmZceGZmXHg0OVx4ODlceGM2XHg0OFx4MzFceGM5XHg0OFx4ZjdceGUxXHg1MFx4NDhceGI4XHg5Y1x4OWVceDkzXHg5Y1x4ZDFceDlhXHg4N1x4OWFceDQ4XHhmN1x4ZDBceDUwXHg0OFx4ODlceGUxXHg0OFx4ZmZceGMyXHg0OFx4ODNceGVjXHgyMFx4NDFceGZmXHhkNlx4ODlceGU1XHg4M1x4ZWNceDIwXHgzMVx4ZGJceDY0XHg4Ylx4NWJceDMwXHg4Ylx4NWJceDBjXHg4Ylx4NWJceDFjXHg4Ylx4MWJceDhiXHgxYlx4OGJceDQzXHgwOFx4ODlceDQ1XHhmY1x4OGJceDU4XHgzY1x4MDFceGMzXHg4Ylx4NWJceDc4XHgwMVx4YzNceDhiXHg3Ylx4MjBceDAxXHhjN1x4ODlceDdkXHhmOFx4OGJceDRiXHgyNFx4MDFceGMxXHg4OVx4NGRceGY0XHg4Ylx4NTNceDFjXHgwMVx4YzJceDg5XHg1NVx4ZjBceDhiXHg1M1x4MTRceDg5XHg1NVx4ZWNceGViXHgzMlx4MzFceGMwXHg4Ylx4NTVceGVjXHg4Ylx4N2RceGY4XHg4Ylx4NzVceDE4XHgzMVx4YzlceGZjXHg4Ylx4M2NceDg3XHgwM1x4N2RceGZjXHg2Nlx4ODNceGMxXHgwOFx4ZjNceGE2XHg3NFx4MDVceDQwXHgzOVx4ZDBceDcyXHhlNFx4OGJceDRkXHhmNFx4OGJceDU1XHhmMFx4NjZceDhiXHgwNFx4NDFceDhiXHgwNFx4ODJceDAzXHg0NVx4ZmNceGMzXHhiYVx4NzhceDc4XHg2NVx4NjNceGMxXHhlYVx4MDhceDUyXHg2OFx4NTdceDY5XHg2ZVx4NDVceDg5XHg2NVx4MThceGU4XHhiOFx4ZmZceGZmXHhmZlx4MzFceGM5XHg1MVx4NjhceDJlXHg2NVx4NzhceDY1XHg2OFx4NjNceDYxXHg2Y1x4NjNceDg5XHhlM1x4NDFceDUxXHg1M1x4ZmZceGQwXHgzMVx4YzlceGI5XHgwMVx4NjVceDczXHg3M1x4YzFceGU5XHgwOFx4NTFceDY4XHg1MFx4NzJceDZmXHg2M1x4NjhceDQ1XHg3OFx4NjlceDc0XHg4OVx4NjVceDE4XHhlOFx4ODdceGZmXHhmZlx4ZmZceDMxXHhkMlx4NTJceGZmXHhkMA).


## Compiling From Source

This program is intended to be compiled with the C/C++ compiler from Microsoft. You can use the `Developer Command Prompt` after installing the free/community version to compile using `cl`. An example of this command would be:

```cl sclauncher.c```

This will produce the exectuable ```sclauncher.exe```.