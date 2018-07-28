Original Pip installer from https://bootstrap.pypa.io/get-pip.py.
It will be used for IDA 6.9 and previous version of IDA, where pip was not shipped with the python. 
We check if pip can be used; if not, install pip. 
By using pip, we can get rid of the msi installer of cefpython. 
Msi installers are no longer available for new version of these two libraries.

For security purpose, you may want to download and replace these dependencies by yourself. 