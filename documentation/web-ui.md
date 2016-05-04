# Kam1n0 Web UI Tutorial 

* [Kam1n0 Web UI](#kam1n0-web-ui)
  * [Preparing the Data](#preparing-the-data)
  * [Create a Repository and Run the Kam1n0 Service](#start-a-repository)
  * [Index a Binary File](#index-a-binary-file)
  * [Search with an Assembly Function](#search-with-an-assembly-function)
  * [Search with a Binary File](#search-with-a-binary-file)
  * [Browse a Clone Search Result](#browse-a-clone-search-result)

## Kam1n0 Web UI

Starting from version 1.x.x we include a set of web-based user interface for Kam1n0. Basically it provides searching and administrating functionalities. In this tutorial, we go through a simple index and search case using the engine and plugin. 

## Preparing the data

Suppose we have two binary files ```libpng-1.7.0b54.dll``` from libpng and  ```zlib-1.2.7.dll``` from zlib. These two files are included in the `example.zip` file in our release. We suggest you to try them first as to be consistent with the following descriptions. You may index other binary files later as you wish. We try to index both of them  and search the second one ```zlib-1.2.7.dll``` against it.

## Create a Repository and Start the Engine

In this step we need to create a repository and start the Kam1n0 engine. Create a repository using the Kam1n0 workbench. Click the `new` button and pick a folder for this repository. Select `metapc.xml` in the drop-down box as architecture. Name this repository anything you like. An example is given in the figure below: 

![image](https://cloud.githubusercontent.com/assets/8474647/15006258/dfc3b188-119c-11e6-9cfd-058d25654e9b.png)

Select the newly created repository in the upper table and click the `start` button to run the Kam1n0 engine. More details on creating repository and starting Kam1n0 engine can be found in our workbench tutorial. 

Your default browser should pop up a login page after a couple seconds. It is the portal to the web interface. The default username and password are both `admin`. After logging in, you can see Kam1n0's main web user interface as below:

![image](https://cloud.githubusercontent.com/assets/8474647/15006493/856e870a-119f-11e6-8ed2-432dc3b929f1.png)

There is a navigation bar on the left and it shows the links to four web pages. Respective descriptions are given below:

|Page name|Functionalities|Required privilege|
|-----------------|---------------------|----|
|Dashboard|Manage indexed binaries and user privilege|Admin|
|Clone Search|Search with an assembly function or fragment|User|
|Composition Analysis|Search with a binary file|User|
|Support|Links to our Github home page|User|

To save some space, you can minimize the navigation bar by clicking this button:

![image](https://cloud.githubusercontent.com/assets/8474647/15006669/8c34c17a-11a0-11e6-8802-676823666825.png)

## Index a Binary File

By clicking the `Dashboard` link on the navigation bar, you will be directed to the administration portal. Basically this page contains multiple boxes that show different information. The tile of each box is quite self-explained. Thus we won't go into details of these boxes. It is noted that we have not implemented the `Search Queries` and `Spark job` boxes yet. For the `Registered user` box, the `user roles` field is a multiple choice box. Make sure you select both the `user` and `admin` roles when you are creating or updating an admin user.

Now let's index the two binary files in the work through example. We start with the first file `zlib-1.2.7.dll`. Scroll down the web page to the `Index a binary file` box, you can find the form for indexing a binary. Simply pick the `zlib-1.2.7.dll` file by clicking the `choose files` button. 

![image](https://cloud.githubusercontent.com/assets/8474647/15006924/754efed8-11a2-11e6-9676-7ff36a2772a2.png)


After that, click the `submit` button. You can see the progress bars are being created continuously with displayed messages. If no error occurs, you will find a new entry `zlib-1.2.7.dll` in the `indexed binaries` table below the progress bars (as shown in the figure below).

![image](https://cloud.githubusercontent.com/assets/8474647/15006936/9390dd6c-11a2-11e6-97c0-c8e3b96780f1.png)

For large binary files it may take a while to index. You can leave this page or close the browser while waiting. Anytime when you are back to the dashboard page you will see the progress again. It is noted that each admin account can only run an indexing job at a time.

Follow the same procedure to index the file `libpng-1.7.0b54.dll`. Now we have two indexed binaries:

![image](https://cloud.githubusercontent.com/assets/8474647/15006977/e20bfa1c-11a2-11e6-8af1-f3267b39d47d.png)


## Search with an Assembly Function

Next, we want to search an assembly function against the repository. By clicking the `clone search` link on the navigation bar, we are redirected to the assembly function/fragment search page. Basically it has a text box with a search button.

![image](https://cloud.githubusercontent.com/assets/8474647/15007024/522fc0bc-11a3-11e6-9c7d-e016514e1e5c.png)

You can enter or copy-and-paste an assembly function/fragment into the box. For this example, we use the adler32 function. Simply click on the link above the upper-right corner of the input box. The example function is copied into the box. Then click the search button. Usually it takes around  1 second to complete the search. It is noted that the search speed is a litter bit slower when the database engine is still warming up at the beginning. 

After the search request is completed, the clone result will be rendered as follow:

![image](https://cloud.githubusercontent.com/assets/8474647/15020692/2ec97bb0-11f1-11e6-9a6f-c6cd9eb73de7.png)

Basically the results are rendered in different views.

### The Clone Graph View and the Clone List View

The `Clone Graph View` can be dragged and zoomed in/out with mouse scrolling. Each circle represents a function. Each color represents different binary file. A link between two nodes indicates their similarity. The blue circle in the center is our query. By double-clicking on the blue node in the center, we can see a list of clones of the query.

![picture2](https://cloud.githubusercontent.com/assets/8474647/15021218/8973868a-11f3-11e6-8228-48effe4e786e.png)


Besides of the `Clone Graph View`, there is a `Clone List View` on the other tab. Instead of showing the clone relationship in a force graph, the `Clone List View` shows it in a tree structure. It is much easier to browse when the number of clone is large.

![picture1](https://cloud.githubusercontent.com/assets/8474647/15021171/51e4ee52-11f3-11e6-9cf0-f201cc991458.png)

By clicking on any entry in the `Clone Graph View` and the `Clone List View` you can see details of the given assembly function clone pair in the following views.

### The Flow Graph View

The `Flow Graph View` explores the cloned control flow graph structure between two functions. The cloned areas are highlighted in different convex hubs. As you can see in this example, even though two functions have different entry blocks, they share several cloned subgraphs. Each is highlighted using a convex hub with a different color. Currently, we ignore blocks with a single instructions. Both graphs can be zoomed in/out and dragged. We provide a scroll (blue) for each of them.

![image](https://cloud.githubusercontent.com/assets/8474647/15021624/e31832ce-11f5-11e6-8412-75ff03b733c1.png)

### The Text Diff View and the Clone Group View

The `Text Diff View` tries to fully ally two assembly functions using a basic string alignment algorithm. It is useful to compare two functions with a high degree of similarity. The lines with a red background mean deletion; while the ones with a green background mean addition.

![image](https://cloud.githubusercontent.com/assets/8474647/15021741/7966ec0c-11f6-11e6-8187-2af8c3040207.png)


The `Clone Group View` lists different cloned subgraphs and compares their differences. The panel below two text columns lists these cloned subgraphs as cloned groups. Each group consists of pairs of cloned basic blocks between two functions. These basic blocks belong to the same group, since they can be connected in the control flow. By clicking on each clone pair, the above two text views will jump to the corresponding basic blocks and compare their differences using string alignment.

![image](https://cloud.githubusercontent.com/assets/8474647/15021943/5d59baac-11f7-11e6-9bc6-2b8bcd363760.png)


## Search with a Binary File

Next, we try to search with a binary file. First, we navigate to the `Composition analysis` page using the navigation bar on the left. As you can see in the figure below, basically this page contains a file upload form. 

![image](https://cloud.githubusercontent.com/assets/8474647/15022028/b5ceb926-11f7-11e6-89ca-2eb9dc8e6ebb.png)

Simply pick the binary file `zlib-1.2.7.dll` and click the `submit` button. There is an threshold hold value which indicates the minimum similarity value for a clone to be included in the search result. You will see progress bar being continuously generated and updated with different messages.

![image](https://cloud.githubusercontent.com/assets/8474647/15022121/1fba5534-11f8-11e6-86c2-0df7422cd881.png)

For large binary files it may take a while to index. You can leave this page or close the browser while waiting. Anytime when you are back to the dashboard page you will see the progress again. It is noted that each admin account can only run a searching job at a time.

After the search is completed, you will be directed to a result render page as shown in the figure below:

![picture3](https://cloud.githubusercontent.com/assets/8474647/15022377/5d8e3d70-11f9-11e6-8b6d-2b0b03163fdb.png)

The rendering page consists of several components:

### The Summary Boxes

At the top of the page, there are two summary boxes which provide statistics about clones between the query and a binary file in the repository.  In this example, we can see that for libpng we find 123 clones with similarity more than 0.5. For zlib, we find 534 clones (99%) with similarity more than 0.5. We know that the query is exactly the same binary as the binary file zlib-1.2.7.dll in the repository. Kam1n0 skip assembly functions with a length less than 2 lines, thus we don't get a 100% similarity here.

![image](https://cloud.githubusercontent.com/assets/8474647/15022753/231bb134-11fb-11e6-9c18-07cd5a033bbe.png)

### The Address Bar

The address bar displays a list of assembly function from the submitted query. It is sorted according to the starting address of the function. If the binary file is very large, the web UI will divide the address range into different pages. Through the dropdown box above you can select different pages. Each line in the address bar represents a function. By using the horizontal scroll at the bottom of the address bar, you can zoom in or out to see the name of the functions.

![picture4](https://cloud.githubusercontent.com/assets/8474647/15022593/66e3760a-11fa-11e6-8c48-d97fff5c998c.png)

The background color of a specific function indicates that Kam1n0 finds a clone in the repository belongs to a specific binary file. The mapping between color and binary name can be found in the box `Color Legend`.

Each line of the address bar is clickable. By clicking it you can see a list of clones related to that clicked assembly function in the box `Clone List`. The clones are organized into a table and sorted by similarity. Click on the header to select which column you would like to use for sorting the table.

![picture5](https://cloud.githubusercontent.com/assets/8474647/15022958/1d24526c-11fc-11e6-9636-0af47ae5c88c.png)

By clicking any entry in the table, you can see the details of a given clone in the views below. These views are the same as the ones that we discussed in last section.

![image](https://cloud.githubusercontent.com/assets/8474647/15023073/bfa45c76-11fc-11e6-837e-e679f99fa407.png)


## Browse a Clone Search Result

After Kam1n0 completes a search query with a binary file, it will generate a `.kam` file which contains all the details about the query and the search results. The kam file can be found at %repository_directory%/tmp/%user_name%/. Specifically, this file contains serveral B-Tree which indexs the following information:

* the assembly functions of the query
* the assembly functions of all the involved assembly functions in the repository
* the clone details

This file can be copied to the other machine which may not have access to your repository. The file can be open using Kam1n0 workbench. By clicking the `File` item on the menu bar and the `Browse result` entry in the sub-menu, you can select a kam file to browse. 

![image](https://cloud.githubusercontent.com/assets/8474647/15023570/06a728e0-11ff-11e6-862f-5fd0bd90e761.png)

After that, you will see a new tab is created in the workbench showing logs for rendering the selected kam file. 

![image](https://cloud.githubusercontent.com/assets/8474647/15023664/66c3ef9c-11ff-11e6-80fc-8667eea5744e.png)

By scrolling down the page you will see a link to show the rendered page. 

![image](https://cloud.githubusercontent.com/assets/8474647/15023715/a8dcf39c-11ff-11e6-904a-0a86313c0466.png)

This link will direct you to the same web interface that we discussed above. Below are some facts about browsing the kam file:
* You can browse several kam file simultaneously using the workbench. Each of them will be associated to a newly created tab in the workbench.
* You can browse the kam file even when the Kam1n0 engine is running. They operate on different ports.
* Closing a newly created tab in the workbench will shutdown the webpage for rendering its associated kam file.  
* You can not browse the same kam file using two tabs. One of them will wait for the other one to open the file.
* Closing the workbench will shutdown all the webpage for rendering kam file
* If the workbench is shutdown abnormally, its sub-processes are still alive and you need to manually kill all the java process in the system task manager.


