# DisableDynamicLoadAddress

Simple program to disable the DYNAMIC_BASE* flag on Windows PE files (.exes, .dlls, etc...),
which will force the program to load to the same address each run. 
This allows for easier debugging as now breakpoint addresses don't need to change between runs.

*https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
