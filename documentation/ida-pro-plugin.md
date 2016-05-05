# IDA Pro Plug-in Tutorial

* [IDA Pro Plug-in Tutorial](#tutorial)
  * [Functionalities](#functionalities)
  * [Walk through example](#walk-through-example)
    * [Preparing the data](#preparing-the-data)
    * [Start the engine](#start-the-engine)
    * [Indexing](#indexing)
    * [Search and add comments](#search-and-add-comments)
  * [How does the Plugin Work](#how-does-the-plug-in-work)
    * [User Interface](#user-interface)
    * [Synchronization](#synchronization)
    * [Communication](#communication)

The IDA Pro plug-in for Kam1n0 creates a folder ```~/Kam1n0/``` to store the plug-in data and errors.
This tutorial first introduces Kam1n0's basic functionalities and then goes through a simple index and search example. 

## Functionalities
The Kam1n0 engine with the plug-in provides the functionalities to index and search assembly functions. 

Icon | Functionality | Description | Hot key
----------|---------------- | -------------------- | -----------
![search](https://cloud.githubusercontent.com/assets/8474647/9765944/9ef7df76-56e4-11e5-86c8-20bc1589fe2c.png)| Search current function | Search the function at current address | Ctrl+Shift+S
![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png)| Select functions to search | Select functions to search | Ctrl+Shift+A
![upload](https://cloud.githubusercontent.com/assets/8474647/9766055/17aa5e76-56e5-11e5-8293-9e72357431f1.png)| Index current function | Index the function at current address | Ctrl+Shift+K
![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png)| Select functions to index | Select functions to index | Ctrl+Shift+J
![setting-cnn](https://cloud.githubusercontent.com/assets/8474647/9766145/711b3f98-56e5-11e5-8797-3952bf9c0916.png)| Manage connections | Manage connections to different repositories | NA
![setting](https://cloud.githubusercontent.com/assets/8474647/9766158/8a598906-56e5-11e5-8fce-722c49665e89.png) | Manage storage | Mange local/remote accounts and storage | NA
![page_edit](https://cloud.githubusercontent.com/assets/8474647/15024789/679c2a60-1204-11e6-8c91-e964581fc04c.png) | Fragment search (new) | Search with the selected assembly fragment | NA

These functionalities can be found in the:

* IDA Pro Search Toolbar:  

     ![image](https://cloud.githubusercontent.com/assets/8474647/9766506/40b20128-56e7-11e5-9720-37205bc024b5.png)

* IDA Pro Functions Window:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9867551/06fad3ce-5b3d-11e5-835f-9faba1f37962.png)


* IDA Pro Search Menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/15024887/c7bcc18e-1204-11e6-8287-fd4073e20e43.png)


* IDA Pro Edit Menu:

     ![image](https://cloud.githubusercontent.com/assets/8474647/9867835/e3d14ea2-5b3f-11e5-8eac-7e300a09b4f9.png)

* IDA Pro View A (popup menu): 

     ![image](https://cloud.githubusercontent.com/assets/8474647/15024918/eaed6744-1204-11e6-9498-da983f9b4cf7.png)



Even though you can select functions from the popup menu of the ```IDA Pro Functions Window``` to search/index functions, using ![searchs](https://cloud.githubusercontent.com/assets/8474647/9765980/c69949c0-56e4-11e5-970f-74a4f48e651e.png) and ![uploads](https://cloud.githubusercontent.com/assets/8474647/9766100/420cccf8-56e5-11e5-8c2b-b0dbdc19de3c.png) at other places (e.g. toolbar) opens a ```Selection Window``` which provides a more detailed configuration for multiple search. While using the plugin, we recommend to keep the ```Output Window``` open in IDA Pro. 

![image](https://cloud.githubusercontent.com/assets/8474647/9766922/84f86aaa-56e9-11e5-936a-0f5483686dc5.png)
![image](https://cloud.githubusercontent.com/assets/8474647/9766925/8f145134-56e9-11e5-9b98-7c0ca4e53039.png)



For example, you can apply different filters and choose which connection you want to use to search/index them.

## Walk through example
Let's go through a simple index and search case using the engine and plugin. 

### Preparing the data
Suppose we have two binary files ```libpng-1.7.0b54.dll``` from libpng and  ```zlib-1.2.7.dll``` from zlib. These two files are included in our release file ```Kam1n0_IDA_Pro_v0.0.2.zip```. We suggest you to try them first as to be consistent with the following descriptions. You may index other binary files later as you wish. We try to index the first binary file ```libpng-1.7.0b54.dll``` and search the second one ```zlib-1.2.7.dll``` against it.

### Start The engine

In this step, we need to create a repository and start the Kam1n0 engine. To create a repository using the Kam1n0 workbench, click the `new` button and pick a folder for this repository, select `metapc.xml` in the drop-down box as architecture, and assign a name to the repository . An example is given in the figure below: 

![image](https://cloud.githubusercontent.com/assets/8474647/15006258/dfc3b188-119c-11e6-9cfd-058d25654e9b.png)

Select the newly created repository in the upper table and click the `start` button to run the Kam1n0 engine. More details on creating repository and starting Kam1n0 engine can be found in our workbench tutorial. Your default browser should pop up a login page after a couple seconds. Close the browser since we are not using the web user interface at this moment. Details about the web interface can be found in our web UI tutorial.

### Indexing

Open IDA Pro and disassemble the ```libpng-1.7.0b54.dll``` binary file as usual. Click on the ```Manage Connection Button``` in the toolbar ![cnn](https://cloud.githubusercontent.com/assets/8474647/9767812/03b32f16-56ee-11e5-9284-c628c33e4031.png). You are now able to review and edit the connections of the plug-in. There is already a default connection for the local engine. These connections will be stored for future use. 

![cnnw](https://cloud.githubusercontent.com/assets/8474647/9767976/efda63d2-56ee-11e5-9cff-e15a68fa7312.png)

To index the functions, click on the ```Select Functions to Index Button``` in the toolbar (or in the other aforementioned location). Check the ```Select All Functions Option``` and click the ```Index Button``` (shown as Steps 1, 2 and 3 in the image below). Each indexed binary is uniquely identified by its path, and each indexed function by its binary ID and starting address. 

![image](https://cloud.githubusercontent.com/assets/8474647/9768328/dc0c1e02-56f0-11e5-9c12-3f231a299159.png)

Wait until the indexing process finishes as shown in the ```Progress Form```. Detailed progress information is printed in the ```IDA Pro Output Window```. Press the ```OK Button``` to close the form when you see 100% shown.

![image](https://cloud.githubusercontent.com/assets/8474647/9867900/89e2dd88-5b40-11e5-832c-da6dd61170dd.png)

![image](https://cloud.githubusercontent.com/assets/8474647/15025250/6ae89ac6-1206-11e6-9bd7-12bca8668495.png)


## Search and add comments
Open IDA Pro and disassemble the target ```zlib-1.2.7.dll``` binary file as usual. Click on the ```Select Functions to Search Button``` in the toolbar ![image](https://cloud.githubusercontent.com/assets/8474647/9768419/95e4bba4-56f1-11e5-8c42-9bee9a5cba28.png). Suppose we want to search for the ```alder32``` and ```compress2``` functions. Select them using ctrl+click in the list. Click on the ```Search Button``` (shown as Step 1 and Step 2 in image below).

![image](https://cloud.githubusercontent.com/assets/8474647/9867961/42fec16a-5b41-11e5-89c1-86ff62985fbe.png)

You will see a progress form during the search. The search should end in seconds, and it will pop up two windows: the `Kam1n0` window and the `Clone Tree` window.

![image](https://cloud.githubusercontent.com/assets/8474647/15025384/06b73084-1207-11e6-95f4-31a05c63e992.png)

### The Clone Graph View and the Clone List View

![picture8](https://cloud.githubusercontent.com/assets/8474647/15025961/dad4a21e-1209-11e6-8fd3-b6b417241e7f.png)

The `Kam1n0` window contains a ```Clone Graph View```. It can be dragged and zoomed in/out with mouse scrolling. Each circle represents a function. Each color represents different binary. A link between two nodes indicates their similarity. The two blue circles are our selected queries. By double-clicking on the ```alder32``` node (blue node in the center), we open the ```Clone List ``` window as shown below:

![picture7](https://cloud.githubusercontent.com/assets/8474647/15025769/e1f104b2-1208-11e6-81d0-019e298a254f.png)

The window lists all the connected nodes with more details about their similarity and binary name. There are three views to inspect each result. We will discuss them in the next section.

Instead of showing the clone relationship in a force graph, the `Clone Tree` window shows it in a tree structure. It is much easier to browse the clones when the number of clone is large.

![picture6](https://cloud.githubusercontent.com/assets/8474647/15025790/fe87c87c-1208-11e6-8e3c-d29ff5ee7c76.png)


Similar to the ```Clone List ``` window, each entry in the `Clone Tree` window has three different views. We use these views to compare clones. By clicking on any of them, a new window will be popped up with a different view.


### The Flow View 

The Flow View explores the cloned control flow graph structure between two functions. The cloned areas are highlighted in different convex hubs. As you can see in this example, even though two functions have different entry blocks, they share several cloned subgraphs. Each is highlighted using a convex hub with a different color. Currently, we ignore blocks with less than 4 instructions. Both graphs can be zoomed in/out and dragged. We provide a scroll (blue) for each of them. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868051/30f424b4-5b42-11e5-8614-a19f8ab205d4.png)

### The Text-Diff View

The Text-Diff View tries to fully align two assembly functions using a basic string comparison algorithm. It is useful to compare two functions with a high degree of similarity. The lines with a red background mean deletion while the ones with a green background mean addition. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868058/448e88c0-5b42-11e5-97b5-fd5a857d45c4.png)


### The Clones View

The Clones View lists different cloned subgraphs and compares their differences. The panel below the two text views lists the cloned subgraphs as cloned groups. Each group consists of pairs of cloned basic blocks between two functions. These basic blocks belong to the same group since they can be connected in the control flow. By clicking on each clone pair, the above two text views will jump to the corresponding basic blocks and compare their differences using string alignment. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868089/b6f03026-5b42-11e5-8368-e304ba7674c4.png)

In the Clone View, you are able to add rich comments to each assembly code instruction of each function. Move the mouse to the line for which you want to add a comment and click on the ```+``` button to show the ```Comment Form```. Markdown language is supported. 

![image](https://cloud.githubusercontent.com/assets/8474647/9868101/e766cecc-5b42-11e5-891c-b559f78cbe28.png)

### Assembly Fragment Search

![picture10](https://cloud.githubusercontent.com/assets/8474647/15026377/31a10554-120c-11e6-8b1b-48af7c536029.png)

Starting from version 1.x.x, we support assembly fragment search in IDA Pro. This is still an experimental feature at this moment. You can simply select a couple lines of assembly code and right click on it to pop out the menu. Select the entry `Query fragment`. You will see a pop up window in which you are able to edit the selected assembly code. Then click the `search` button.

![image](https://cloud.githubusercontent.com/assets/8474647/15026263/879ba42e-120b-11e6-9efd-cbf70decf2e9.png)

After that, a search progress form will pop up and the search will finish in seconds. The same windows as we see for assembly function search are popped up once the search completes. 

![image](https://cloud.githubusercontent.com/assets/8474647/15026314/d39ff226-120b-11e6-954c-927ddb0c4959.png)


# How does the Plug-in Work

The plug-in is written inPpython using ```idaapi```. The root of this repository is the Windows installer. The source code of the plug-in can be found [here](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro/tree/master/Kam1n0WinSetupProject/bin_release/plugins). 

## User Interface

The user interface consists of two parts: 
* The native ```idaapi``` forms and controls: the Connection Management Form, the Search Progress Form, the Index Progress Form, the Select Function to Search Form, and the Select Function to Index Form.
* The local webpages: the Clone Graph View, the Clone List View, the Text-Diff View, the Flow View, and the Clones View. These local webpages are rendered using the embeded Chromium shipped with cefpython, and the frame used to hold Chromium is wxpython. We tried cefpython with the build-in pyside of IDA Pro. Unfortunately, pages cannot be rendered, so we switch to wxpython. 

## Synchronization

We find it difficult to update the IDA Pro UI asynchronously using ```idaapi```. If a thread other than the main thread updates the interface while the user interacts with (e.g. clicks on) the interface, IDA Pro will freeze/crash. 

## Communication

To interact with the Kam1n0 web services, we use the built-in ```urllib``` in Python to send requests and the ```json``` lib to parse the json results. After that, the json results are passed to javascripts using ```cefpython```. 
