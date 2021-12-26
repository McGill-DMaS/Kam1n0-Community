# FAQ for Kam1n0 IDA Pro Plugin

## Cannot Start IDA Pro or IDAPython does not run correctly

This is probably the wrong python version is installed. Not every version works. The one that works for certain is Python 3.7 from python.org.

## ModuleNotFoundError: No module named 'cefpython3'

If you installed cefpython3 and when you run python from command line, you can import cefpython3, then it is because there are multiple pythons installed on your computer and IDA Pro is using another one. Even though the IDA Pro output window shows you the python version is the one you are using, it loads the libraries from the default python version written in the registry: HKEY_LOCAL_MACHINE\SOFTWARE\Python\PythonCore\3.7\InstallPath\. So you need to install the package for that python.
