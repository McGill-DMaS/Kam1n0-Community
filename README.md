# What is Kam1n0?

Kam1n0 is a scalable system that supports assembly code clones search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or a give target binary file. Kam1n0 plugin is a plugin for IDA-Pro user to perform the indexing the searching capabilities on Kam1n0 via the IDA user interface.


* [Installation](#Installation)
* [Tutorial](#Tutorial)
* [How does the Plugin Works](#How-does-the-Plugin-Work)


# Installation

The current distribution of Kam1n0 plugin for IDA-Pro is bundled with a local Kam1n0 engine. In order to have it working properly, you need the following dependencies:

* [Required] The latest 8.x JRE/JDK distribution from [Oracle](http://www.oracle.com/technetwork/java/javase/downloads/index.html) (x64/x86).
* [Required] The latest version of IDA Pro with the python plugin [idapython](https://code.google.com/p/idapython/) plugin installed. The python plugin and runtime should have already been shipped with IDA-Pro. Re-install IDA-Pro if necessary. 

Next, download the latest ```.msi``` installation file for Windows at our [release page](https://github.com/steven-hh-ding/Kam1n0-Plugin-IDA-Pro/releases). Follow the instructions to install the plugin and runtime. Please note that the plugin has to be installed at the IDA-Pro plugins directory which is located at ```$IDA_PRO_PATH$/plugins```. For example, on Windows, the path could be ```C:/Program Files (x86)/IDA 6.8/plugins```. The installer will validate the path. 

# Where does Kam1n0 store the data?
At the end of installation, the installer will ask you to select the path for storing local data. All the data and log files will be stored there. Also it creates a folder ```~/Kam1n0/``` to store plugin data and errors. The local kam1n0 engine can be found at the installation path. You can customize its configuration file ```kam1n0-conf.xml```.

# Tutorial
This tutorial will firstly introduce Kam1n0's basic functionalities; and then walk you through a simple index and search example. 

## Functionalities
The Kam1n0 engine with the plugin provide you the functionalities to index and search assembly functions. 

Icon | Functionality | Description | Hot-key
----------|---------------- | -------------------- | -----------
![search](https://cloud.githubusercontent.com/assets/8474647/9765944/9ef7df76-56e4-11e5-86c8-20bc1589fe2c.png)| Search current function | Search the function at current EA address | Ctrl+Shift+S
![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png)| Search selected functions | Search the selected functions | Ctrl+Shift+A
![upload](https://cloud.githubusercontent.com/assets/8474647/9766055/17aa5e76-56e5-11e5-8293-9e72357431f1.png)| Index current function | Index the function at current EA address | Ctrl+Shift+K
![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png)| Index selected functions | Index the selected functions | Ctrl+Shift+J
![setting-cnn](https://cloud.githubusercontent.com/assets/8474647/9766145/711b3f98-56e5-11e5-8797-3952bf9c0916.png)| Manage connections | Connections to different repository | NA
![setting](https://cloud.githubusercontent.com/assets/8474647/9766158/8a598906-56e5-11e5-8fce-722c49665e89.png) | Manage storage | Mange local/remote accounts and storage | NA

These functionalities can be found at:

* IDA search toolbar:  

     ![image](https://cloud.githubusercontent.com/assets/8474647/9766506/40b20128-56e7-11e5-9720-37205bc024b5.png)

* IDA function window:

     ![menu-search](https://cloud.githubusercontent.com/assets/8474647/9766673/33187f14-56e8-11e5-99f9-e430fc6c4c63.png)

* IDA search menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9766626/e77efad8-56e7-11e5-8685-c8146b52ab3b.png)


* IDA edit menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9766646/010cf5fe-56e8-11e5-84e3-fefe0f132187.png)


* IDA-view A (Pop-up menu): 

     ![view-a](https://cloud.githubusercontent.com/assets/8474647/9766486/24253840-56e7-11e5-844a-19ab8ada57b9.png)


Even though you can select functions at the popup menu of the IDA's *Function Window* to search/index functions, using ![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png) and ![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png) at other places (e.g. toolbar) can open a selection window which provides more detailed configuration for multiple search. 

![image](https://cloud.githubusercontent.com/assets/8474647/9766922/84f86aaa-56e9-11e5-936a-0f5483686dc5.png)
![image](https://cloud.githubusercontent.com/assets/8474647/9766925/8f145134-56e9-11e5-9b98-7c0ca4e53039.png)



For example, you can apply different filter and choose which connection you want to use to search/index them.

## Walk-through example
Let's go through a simple index and search case using the engine and plugin. 

### Preparing the data
Suppose we have a binary file [zlibwapi.dll](https://github.com/steven-hh-ding/Kam1n0-Plugin-IDA-Pro/raw/master/example/zlibwapi.dll) from zlib 2.7. This sample file is included in ```Kam1n0_windows.zip```. We suggest you to try this binary file first as to be consistent with following descriptions. You may index other binary files later as you wish.  We copy this binary as ```zlibwapi.dll``` and ```zlibwapi2.dll```. We try to index the first binary file and search the second one against the first binary file. It is important that they have different filenames.

### Start the engine
To start with, we need to start the kam1n0 storage and search engine. You can run it from apps in your start menu or desktop shortcut (if you chose to create one).

![image](https://cloud.githubusercontent.com/assets/8474647/9767402/1303ad08-56ec-11e5-8379-04d7007d5d5c.png)
 
Kam1n0 is a console application. It is fine to see some warning messages at the first run because the engine cannot find lots of thing and trying to create them. Please note that if you choose a system path to be the storage directory, you need to have the engine run as administrator. 

Kam1n0 should popup a browser with a login page as shown below. The default username and password are both ```admin```. You can change it later after you are logged in. At this moment you may close the browser first. We can manage it through IDA plugin.

![login](https://cloud.githubusercontent.com/assets/8474647/9767556/c6e50cf4-56ec-11e5-8f41-e3f9a0668050.png)

### Indexing

Open IDA-Pro and disassemble the ```zlibwapi.dll``` binary file as usual. Click on the manage connection button at the toolbar ![cnn](https://cloud.githubusercontent.com/assets/8474647/9767812/03b32f16-56ee-11e5-9284-c628c33e4031.png). You are now able to review and edit connections of the plugin. There is already a default connection for local engine. These connections will be stored for future use. 

![cnnw](https://cloud.githubusercontent.com/assets/8474647/9767976/efda63d2-56ee-11e5-9cff-e15a68fa7312.png)

To index the functions, click at the ```index selected functions``` button at the toolbar (or other aforementioned location ). Check the ```Selected all functions``` option; and click the ```Index``` button (shown as Step 1, 2 and 3 in the image below). Each indexed binary is uniquely identified by its path and each indexed function is uniquely identified by its binary's id and its starting ea address. 

![image](https://cloud.githubusercontent.com/assets/8474647/9768328/dc0c1e02-56f0-11e5-9c12-3f231a299159.png)

Wait until the indexing process finishes as shown in the progress form. You may need to scroll down the list. Press the OK button to close the form when you see 100% at the end of the list.

![image](https://cloud.githubusercontent.com/assets/8474647/9768256/7eed4cbe-56f0-11e5-9080-d747454bb2c9.png)

## Search and add comments
Open IDA-Pro and disassemble the target ```zlibwapi2.dll``` binary file as usual. Click on the ```search selected functions``` button at the toolbar ![image](https://cloud.githubusercontent.com/assets/8474647/9768419/95e4bba4-56f1-11e5-8c42-9bee9a5cba28.png). Suppose we want to search the ```alder32``` and ```compress2```. Select them using ctrl+click on the list. Click on the search button. (As the Step 1 and Step 2 shown in picture below)

![image](https://cloud.githubusercontent.com/assets/8474647/9768549/61d0de0a-56f2-11e5-81ba-df77b27c4955.png)

The search should end in seconds. You will be able to see a progress form and the ```clone graph view```. 

![image](https://cloud.githubusercontent.com/assets/8474647/9768653/0ddec586-56f3-11e5-8630-d51ec9e326be.png)

The graph view can be dragged by mouse and zoom in/out by scrolling. Different circle with different name stands for different function. Different color stands for different binary. A link between two nodes represents their similarity. The two blue circles are our selected target functions. By double-clicking on the ```compress2``` node (blue color), we open the ```clone list``` window as shown below:

![image](https://cloud.githubusercontent.com/assets/8474647/9768785/e8abe7ca-56f3-11e5-814f-9d9c377db3c1.png)

The window lists all the connected nodes with more details about similarity and binary name. There are three views to inspect each result: 

![image](https://cloud.githubusercontent.com/assets/8474647/9768873/861dda4a-56f4-11e5-901c-9a64aad17b00.png)


### The flow view: 

This flow view explores cloned control flow graph structure between two functions. The cloned areas are highlighted in different convex hub. In this example, there is only one cloned sub-graph; therefore, there is only one convex hub. Currently we ignore blocks with length less than 4 lines of code. Both graphs can be zoom in/out and dragged. We provided a scroll (blue) for each of them. 

![image](https://cloud.githubusercontent.com/assets/8474647/9768939/f43b4ca6-56f4-11e5-9094-f066cbc999ea.png)


### The text-diff view

The text-diff view tries to fully allies two assembly function. It is useful to compare two functions with high degree of similarity. The lines with red background mean deletion; and the lines with green background mean addition. 

![image](https://cloud.githubusercontent.com/assets/8474647/9769084/d348879c-56f5-11e5-87fe-fc0ebb29987a.png)



### The Clones view

The clones view lists different cloned sub-graphs and compares their differences. The panel below two text views lists these cloned sub-graphs as cloned groups. Each group consists of pairs of cloned basic block between two functions. These basic blocks belong to the same group since they can be connected in the control flow. By clicking on each clone pair, the above two text views will jump to corresponding blocks and compare their differences. 

![image](https://cloud.githubusercontent.com/assets/8474647/9769340/938bbbb8-56f7-11e5-9309-1d170e2adf71.png)


In this clones view, you are able to add rich comment to each line of assembly code for each function. Move the mouse to the line that you want to leave some comment, and click on the ```+``` button to show the comment form. Markdown language is supported. 

![image](https://cloud.githubusercontent.com/assets/8474647/9769527/bddc1bf0-56f8-11e5-99ca-e7d7263b8774.png)


# How the plugin works

