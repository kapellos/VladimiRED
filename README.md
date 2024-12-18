# VladimiRED

VladimiRED (you expect to get one thing and you end up with something else ;-)) is a C# port of Mockingjay injection technique (https://github.com/caueb/Mockingjay) to be used with AppDomainManager Injection Method.

The produced dll injects shellcode into already existing RWE regions via Marshaling avoiding using pinvoke related injection calls.

![image](https://github.com/kapellos/VladimiRED/blob/main/VladimiRED.png)

# Usage
You will need a 64bit AppDomainManager Microsoft Signed application to run this (unless you revert this to a standard console application). 

I suggest the excellent resources by Mr. Mr-Un1k0d3r:

1)https://github.com/Mr-Un1k0d3r/.NetConfigLoader

2)https://raw.githubusercontent.com/Mr-Un1k0d3r/.NetConfigLoader/main/signed.txt

Also you will need some other "vulnerable" dll since the original, which is also used in this project, has limited shellcode space for a CS beacon. You can find them using the python script ([https://github.com/caueb/Mockingjay](https://github.com/caueb/Mockingjay/blob/main/rwx_finder.py)) in everyday computers ;-).

Most importantly you will need a solid shellcode encryption/download method which I do not provide here if you really need to evade EDRs.

# Credits
- Charles Hamilton ([@MrUn1k0d3r](https://twitter.com/MrUn1k0d3r))
- Caue B [caueb](https://github.com/caueb)


