# ![letter-k-icon 2](https://cloud.githubusercontent.com/assets/8474647/9867492/577c7d8a-5b3c-11e5-9334-520bddc3ddc8.png) What is Kam1n0?

Assembly code analysis is a time-consuming process. An effective and efficient assembly code clone search engine can greatly reduce the effort of this process; since it can identify the cloned parts that have been previously analyzed. Kam1n0 is a scalable system that supports assembly code clone search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or a binary file. 

Kam1n0 tries to solve the efficient subgraph search problem (i.e. graph isomorphism problem) for assembly functions. Given a target function (the middle one in the figure below) it can identity the cloned subgraphs among other functions in the repository (the one on the left and the one on the right as shown below). Kam1n0 supports rich comment format, and it  has a IDA Pro plug-in to use its indexing and searching capabilities via the IDA Pro.

![image](https://cloud.githubusercontent.com/assets/8474647/9867360/a130631c-5b3a-11e5-8b76-83afec582886.png)

In this repository we release the initial version of Kam1n0 and its plugin for IDA Pro. It can run on a single workstation/server, and provide clone search service through RESTful web services. The users can connect to the server through IDA Pro. Alternatively it can be deployed on a distributed cluster (next major release).

## Table of Content

* [Installation](#installation)
  * [Where does Kam1n0 store the data](#where-does-kam1n0-store-the-data)
* [Tutorial](#tutorial)
  * [Functionalities](#functionalities)
  * [Walk through example](#walk-through-example)
    * [Preparing the data](#preparing-the-data)
    * [Start the engine](#start-the-engine)
    * [Indexing](#indexing)
    * [Search and add comments](#search-and-add-comments)
* [How does the Plugin Work](#how-does-the-plug-in-work)


# Installation

The current distribution of the Kam1n0 IDA Pro plug-in is bundled with a local Kam1n0 engine. In order to have it work properly, you need the following dependencies:

* [Required] The latest x86 8.x JRE/JDK distribution from [Oracle](http://www.oracle.com/technetwork/java/javase/downloads/index.html) (x86).
* [Required] The latest version of IDA Pro with the [idapython](https://code.google.com/p/idapython/) plug-in installed. The Python plug-in and runtime should have already been installed with IDA Pro. Re-install IDA Pro if necessary. 

Next, download the latest ```.msi``` installation file for Windows at our [release page](https://github.com/steven-hh-ding/Kam1n0-Plugin-IDA-Pro/releases). Follow the instructions to install the plug-in and runtime. Please note that the plug-in has to be installed in the IDA Pro plugins directory which is located at ```$IDA_PRO_PATH$/plugins```. For example, on Windows, the path could be ```C:/Program Files (x86)/IDA 6.8/plugins```. The installer will validate the path. 

## Where does Kam1n0 store the data?
At the end of the installation, the installer will ask you to select the path for storing local data and log files. It also creates a folder ```~/Kam1n0/``` to store plug-in data and errors. The local Kam1n0 engine can be found IN the installation path. You can customize its configuration file ```kam1n0-conf.xml```.

# Tutorial
This tutorial first introduces Kam1n0's basic functionalities and then walk you through a simple index and search example. 

## Functionalities
The Kam1n0 engine with the plug-in provide you the functionalities to index and search assembly functions. 

Icon | Functionality | Description | Hot key
----------|---------------- | -------------------- | -----------
![search](https://cloud.githubusercontent.com/assets/8474647/9765944/9ef7df76-56e4-11e5-86c8-20bc1589fe2c.png)| Search current function | Search the function at current address | Ctrl+Shift+S
![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png)| Select functions to search | Select functions to search | Ctrl+Shift+A
![upload](https://cloud.githubusercontent.com/assets/8474647/9766055/17aa5e76-56e5-11e5-8293-9e72357431f1.png)| Index current function | Index the function at current address | Ctrl+Shift+K
![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png)| Select functions to index | Select functions to index | Ctrl+Shift+J
![setting-cnn](https://cloud.githubusercontent.com/assets/8474647/9766145/711b3f98-56e5-11e5-8797-3952bf9c0916.png)| Manage connections | Manage connections to different repositories | NA
![setting](https://cloud.githubusercontent.com/assets/8474647/9766158/8a598906-56e5-11e5-8fce-722c49665e89.png) | Manage storage | Mange local/remote accounts and storage | NA

These functionalities can be found in:

* IDA Pro Search Toolbar:  

     ![image](https://cloud.githubusercontent.com/assets/8474647/9766506/40b20128-56e7-11e5-9720-37205bc024b5.png)

* IDA Pro Functions Window:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9867551/06fad3ce-5b3d-11e5-835f-9faba1f37962.png)


* IDA Pro Search Menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9867512/a1daab4a-5b3c-11e5-82e6-098a44094fad.png)

* IDA Pro Edit Menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9867835/e3d14ea2-5b3f-11e5-8eac-7e300a09b4f9.png)

* IDA Pro View A (popup menu): 

     ![view-a](https://cloud.githubusercontent.com/assets/8474647/9766486/24253840-56e7-11e5-844a-19ab8ada57b9.png)


Even though you can select functions in the popup menu of the ```IDA PRO Functions Window``` to search/index functions, using ![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png) and ![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png) at other places (e.g. toolbar) open a ```Selection Window``` which provides A more detailed configuration for multiple search. While using the plugin, we recommend you to keep the ```Output Window``` open in IDA Pro. 

![image](https://cloud.githubusercontent.com/assets/8474647/9766922/84f86aaa-56e9-11e5-936a-0f5483686dc5.png)
![image](https://cloud.githubusercontent.com/assets/8474647/9766925/8f145134-56e9-11e5-9b98-7c0ca4e53039.png)



For example, you can apply different filters and choose which connection you want to use to search/index them.

## Walk through example
Let's go through a simple index and search case using the engine and plugin. 

### Preparing the data
Suppose we have two binary files ```libpng-1.7.0b54.dll``` from libpng and  ```zlib-1.2.7.dll``` from zlib. These two files are included in our release file ```Kam1n0_IDA_Pro_v0.0.2.zip```. We suggest you to try them first as to be consistent with the following descriptions. You may index other binary files later as you wish. We try to index the first binary file ```libpng-1.7.0b54.dll``` and search the second one ```zlib-1.2.7.dll``` against it.

### Start the engine
To begin with, we first need to start the kam1n0 storage and search engine. You can run it from apps in your Start Menu or desktop shortcut.

![image](https://cloud.githubusercontent.com/assets/8474647/9767402/1303ad08-56ec-11e5-8379-04d7007d5d5c.png)
 
Kam1n0 is a console application. It is normal to see some warning messages at the first run, as the engine tries to find and create several elements. Please note that if you chose a system path to be the storage directory, you need to have the engine run as administrator. 

Kam1n0 should open a browser with a login page as shown below. The default username and password are both ```admin```. You can change the later after you are logged in. You can close the browser, as we will use IDA Pro. 

![login](https://cloud.githubusercontent.com/assets/8474647/9767556/c6e50cf4-56ec-11e5-8f41-e3f9a0668050.png)

### Indexing

Open IDA Pro and disassemble the ```libpng-1.7.0b54.dll``` binary file as usual. Click on the ```Manage Connection Button``` in the toolbar ![cnn](https://cloud.githubusercontent.com/assets/8474647/9767812/03b32f16-56ee-11e5-9284-c628c33e4031.png). You are now able to review and edit the connections of the plugin. There is already a default connection for the local engine. These connections will be stored for future use. 

![cnnw](https://cloud.githubusercontent.com/assets/8474647/9767976/efda63d2-56ee-11e5-9cff-e15a68fa7312.png)

To index the functions, click on the ```Select Functions to Index Button```at the toolbar (or in the other aforementioned location). Check the ```Select All Functions Option``` and click the ```Index Button``` (shown as Step 1, 2 and 3 in the image below). Each indexed binary is uniquely identified by its path, and each indexed function by its binary's id and its starting address. 

![image](https://cloud.githubusercontent.com/assets/8474647/9768328/dc0c1e02-56f0-11e5-9c12-3f231a299159.png)

Wait until the indexing process finishes as shown in the ```Progress Form```. Detailed progress info is printed in the ```IDA Output Window```. Press the ```OK Button``` to close the form when you see 100% shown in the form.

![image](https://cloud.githubusercontent.com/assets/8474647/9867900/89e2dd88-5b40-11e5-832c-da6dd61170dd.png)

![image](https://cloud.githubusercontent.com/assets/8474647/9867909/9eddea0c-5b40-11e5-9190-812308009793.png)


## Search and add comments
Open IDA Pro and disassemble the target ```zlib-1.2.7.dll``` binary file as usual. Click on the ```Select Functions to Search Button``` at the toolbar ![image](https://cloud.githubusercontent.com/assets/8474647/9768419/95e4bba4-56f1-11e5-8c42-9bee9a5cba28.png). Suppose we want to search the ```alder32``` and ```compress2```. Select them using ctrl+click on the list. Click on the ```Search Button```. (Shown as the Step 1 and Step 2 in image below).

![image](https://cloud.githubusercontent.com/assets/8474647/9867961/42fec16a-5b41-11e5-89c1-86ff62985fbe.png)

The search should end in seconds. You will be able to see a progress form and the ```Clone Graph View```. 

![image](https://cloud.githubusercontent.com/assets/8474647/9867977/6aef8aa6-5b41-11e5-885f-c816afdbbf74.png)

The ```Clone Graph View``` can be dragged and zoomed in/out with mouse scrolling. Each circle represents a function. Each color represents different binary. A link between two nodes indicates their similarity. The two blue circles are our selected target functions. By double-clicking on the ```alder32``` node (blue node in the center), we open the ```Clone List Window``` as shown below:

![image](https://cloud.githubusercontent.com/assets/8474647/9868018/e305557a-5b41-11e5-9dce-d2c7b87ac9f5.png)


The window lists all the connected nodes with more details about thier similarity and binary name. There are three views to inspect each result: 

![image](https://cloud.githubusercontent.com/assets/8474647/9868038/03dd27f0-5b42-11e5-84fd-f3d4abaf0cb8.png)


### The Flow View 

The Flow View explores the cloned control flow graph structure between two functions. The cloned areas are highlighted in different convex hubs. As you can see in this example, even though two functions have different entry blocks, they share several cloned subgraphs. Each is highlighted using a convex hub with different color. Currently we ignore blocks with less than 4 instructions. Both graphs can be zoom in/out and dragged. We provide a scroll (blue) for each of them. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868051/30f424b4-5b42-11e5-8614-a19f8ab205d4.png)

### The Text-Diff View

The Text-Diff View tries to fully ally two assembly functions using basic string comparison algorithm. It is useful to compare two functions with a high degree of similarity. The lines with a red background mean deletion; while the ones with a green background mean addition. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868058/448e88c0-5b42-11e5-97b5-fd5a857d45c4.png)


### The Clones View

The Clones View lists different cloned subgraphs and compares their differences. The panel below two text views lists these cloned subgraphs as cloned groups. Each group consists of pairs of cloned basic blocks between two functions. These basic blocks belong to the same group since they can be connected in the control flow. By clicking on each clone pair, the above two text views will jump to the corresponding blocks and compare their differences using string alignment. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868089/b6f03026-5b42-11e5-8368-e304ba7674c4.png)

In the Clone View, you are able to add rich comments to each assembly code instruction of each function. Move the mouse to the line for which you want to add a comment, and click on the ```+``` button to show the ```Comment Form```. Markdown language is supported. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868101/e766cecc-5b42-11e5-891c-b559f78cbe28.png)


# How does the Plug-in Work

The plug-in is written in python using ```idaapi```. The root of this repository is the windows installer. The source code of the plugin can be found [here](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro/tree/master/Kam1n0WinSetupProject/bin_release/plugins). 

## User Interface
The user interface consists of two parts: 
* The native idaapi forms and controls: Connection Management Form, Search Progress Form, Index Progress Form, Select Function to Search Form, Select Function to Inex Form.
* The local wabpages: the Clone Graph View, the Clone List View, the Text-Diff View, the Flow View, and the Clones View.
* These local webpages are redenered using the embeded chromieum shipped with cefpython; and the frame used to hold chromieum is wxpython. We tried cefpython with the build-in pyside of IDA Pro. Unfortunately pages cannot be rendered, so we switch to wxpython. 
* 

## Synchronization
We find it difficult to update the IDA Pro UI asynchronously. If a thread other than the main thread updates interface and the user interacts with (e.g. click on) the interface at the same moment, the IDA Pro will freeze/crash.  

## Communication
To interact with the Kam1n0 web services, we use the build-in ```urllib``` in python to send request and the ```json``` lib parse the json results. After that json results are pass to javascripts using ```cefpython```. More details can be found at the Connector. 
