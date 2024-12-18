# VladimiRED

VladimiRED (you expect to get one thing and you end up with something else ;-)) is a C# port of Mockingjay injection technique (https://github.com/caueb/Mockingjay) to be used with AppDomainManager Injection Method.
The produced dll injects shellcode into already existing RWE regions via Marshaling avoiding using pinvoke related injection calls.

![image](https://github.com/kapellos/VladimiRED/blob/main/VladimiRED.png)

# Usage
You need a 64bit AppDomainManager Microsoft Signed application to run this (unless you revert this to a standard console application). 
I suggest the excellent resources from Mr. Mr-Un1k0d3r

https://github.com/Mr-Un1k0d3r/.NetConfigLoader
https://raw.githubusercontent.com/Mr-Un1k0d3r/.NetConfigLoader/main/signed.txt

More importantly you will need a solid shellcode encryption/download method which I do not provide here.

# Credits
Mr.Un1k0d3r
caueb


