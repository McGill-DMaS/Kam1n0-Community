#  ![image](https://cloud.githubusercontent.com/assets/8474647/14999349/a530f954-1156-11e6-8d8b-6b2136c322bb.png) What Is Kam1n0?

[![Join the chat at https://gitter.im/steven-hh-ding/Kam1n0-Plugin-IDA-Pro](https://badges.gitter.im/steven-hh-ding/Kam1n0-Plugin-IDA-Pro.svg)](https://gitter.im/steven-hh-ding/Kam1n0-Plugin-IDA-Pro?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Assembly code analysis is a time-consuming process. An effective and efficient assembly code clone search engine can greatly reduce the effort of this process, since it can identify the cloned parts that have been previously analyzed. Kam1n0 is a scalable system that supports assembly code clone search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or binary file. 

Kam1n0 tries to solve the efficient subgraph search problem (i.e. graph isomorphism problem) for assembly functions. Given a target function (the middle one in the figure below) it can identity the cloned subgraphs among other functions in the repository (the ones on the left and the right as shown below). Kam1n0 supports rich comment format and has an IDA Pro plug-in to use its indexing and searching capabilities via IDA Pro. 

Kam1n0 was developed by Steven H. H. Ding under the supervision of Benjamin C. M. Fung in the [Data Mining and Security Lab](http://dmas.lab.mcgill.ca/) at McGill University in Canada. This software won the second prize in the [Hex-Rays Plug-In Contest 2015](https://hex-rays.com/contests/2015/). If you find Kam1n0 useful, please cite our paper:

* S. H. H. Ding, B. C. M. Fung, and P. Charland. Kam1n0: MapReduce-based Assembly Clone Search for Reverse Engineering. In <i>Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (SIGKDD)</i>, 10 pages, San Francisco, CA: ACM Press, August 2016.

![image](https://cloud.githubusercontent.com/assets/8474647/9867360/a130631c-5b3a-11e5-8b76-83afec582886.png)

In this repository we release the initial version of Kam1n0 and its IDA Pro plug-in. It can run on a single workstation/server, and provides clone search service through RESTful web services. The users can connect to the server through IDA Pro. Alternatively, it can be deployed on a distributed cluster (next major release).

##  Release note 2016-05-03 1.0.0-rc1
* [Web UI] Added a web interface for clone search with an assembly function.
* [Web UI] Added a web interface for clone search with a binary file.
* [Kam1n0 Workbench] Added Kam1n0 Workbench for creating and managing multiple repositories on a single workstation.
* [Kam1n0 Core] The binary file clone search result can be shared and browsed on the other machine without access to the repository.
* [Kam1n0 Core] Support indexing and searching for large binary file (>40mb) without limits on system memory.
* [Kam1n0 Core] Support ARM, PowerPC, x86 and amd86 binaries.
* [Kam1n0 Core] Support user-defined processor architecture.
* [Kam1n0 Core] Optimized index structure supports better scalability and clone search quality.
* [Kam1n0 Core] Kam1n0 no longer skips basic blocks which have less than three lines of instruction. Now only single line basic block is skipped; thanks to the new index structure.
* [IDA Pro plug-in for Kam1n0] [Experimental] Added assembly fragment search functionality. 
* [IDA Pro plug-in for Kam1n0] Added a tree view for browsing large number of clones.

## Compatibility:

* The assembly code repositories and configuration files used in previous versions (<1.0.0) are no longer supported by the latest version. See documentations about how to migrate previous repositories. 
* 

## Scalability

* You can index millions of functions in each repository on a single machine. The average response time for a query still stays around 1s; and the average indexing time for a function still stays around 13ms.

#  Installation

The current release of the Kam1n0 consists of two installers: the server core installer and the IDA Pro plug-in installer for Kam1n0. 

<table>
  <tr>
    <th>Installer</th>
    <th>Included components</th>
    <th>Description</th>
  </tr>
  <tr>
    <td rowspan="3">Kam1n0-server.msi</td>
     <td>Core engine</td>
     <td>Main engine providing service for indexing and searching</td>
  </tr>
   <tr>
      <td>Workbench</td>
     <td>An user interface to manage the repositories and the running service.</td>
  </tr>
 <tr>
      <td>Web user interface</td>
     <td>Web user interface for searching/indexing binary file and assembly function.</td>
  </tr>
  <tr>
    <td rowspan="3">Kam1n0-client-idaplugin.msi</td>
     <td>Plug-in</td>
     <td>Connectors and user interface.</td>
  </tr>
<tr>
     <td>Cefpython</td>
     <td>Rendering engine for the user interface.</td>
  </tr>
<tr>
     <td>Wxpython</td>
     <td>Rendering engine for Cefpython.</td>
  </tr>
</table>

## Installing the Kam1n0 Server

The Kam1n0 core engine is purely written in Java. You need the following dependencies:

* [Required] The latest x64 8.x JRE/JDK distribution from [Oracle](http://www.oracle.com/technetwork/java/javase/downloads/index.html).
* [Optional] The latest version of IDA Pro with the [idapython](https://code.google.com/p/idapython/) plug-in installed. The Python plug-in and runtime should have already been installed with IDA Pro. Re-install IDA Pro if necessary. 

Download the ```Kam1n0-server.msi``` file on our [release page](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro/releases). Follow the instructions to install the server. You will be prompted to select an installation path as well as the IDA Pro installation path. The later is optional if the server does not have to deal with any disassembling. In other words, the client side  uses the Kam1n0 plugin for IDA Pro. It is strongly suggested to have the IDA Pro installed with the Kam1n0 server. The current version of Kam1n0 only supports IDA Pro.

## Installing the IDA Pro Plug-in

The IDA Pro plug-in for Kam1n0 is written in Python for logic and in html/JavaScript for rendering. Before installation, it needs the following dependency:

* [Required] The latest version of IDA Pro with the [idapython](https://code.google.com/p/idapython/) plug-in installed. The Python plug-in and runtime should have already been installed with IDA Pro. Re-install IDA Pro if necessary. 


Next, download the ```Kam1n0-client-idaplugin.msi``` installer from our [release page](https://github.com/McGill-DMaS/Kam1n0-Plugin-IDA-Pro/releases). Follow the instructions to install the plug-in and runtime. Please note that the plug-in has to be installed in the IDA Pro plugins directory which is located at ```$IDA_PRO_PATH$/plugins```. For example, on Windows, the path could be ```C:/Program Files (x86)/IDA 6.8/plugins```. The installer will validate the path. 

## Configuring the Kam1n0 Engine

In the previous version of Kam1n0, only a single repository is supported on a workstation, and the configuration files for Kam1n0 stay in the same folder as the engine executable file. Starting from 1.x.x version, Kam1n0 supports multiple repositories on a workstation, and each repository can support different type of processor architecture. Each repository is given a data directory where you can find its configuration files. More details can be found in our Kam1n0 workbench tutorial.

# Documentation
* [Manage repositories with Kam1n0 Workbench](documentation/workbench.md#kam1n0-workbench-tutorial)
  * [Create a repository](documentation/workbench.md#create-a-repository)
  * [Edit a repository](documentation/workbench.md#edit-a-repository)
  * [Remove a repository](documentation/workbench.md#remove-a-repository)
  * [Start or stop the Kam1n0 Engine](documentation/workbench.md#start-or-stop-the-kam1n0-engine)
  * [JVM options for the Kam1n0 Engine](documentation/workbench.md#jvm-options-for-the-kam1n0-engine)
  * [Moving a repository](documentation/workbench.md#moving-a-repository)
* [Web interface tutorial](documentation/web-ui.md#kam1n0-web-ui-tutorial)
  * [Preparing the data](documentation/web-ui.md#preparing-the-data)
  * [Create a repository and start the Engine](documentation/web-ui.md#create-a-repository-and-start-the-engine)
  * [Index a binary file](documentation/web-ui.md#index-a-binary-file)
  * [Search with an assembly function](documentation/web-ui.md#search-with-an-assembly-function)
  * [Search with a binary file](documentation/web-ui.md#search-with-a-binary-file)
  * [Browse a clone search result](documentation/web-ui.md#browse-a-clone-search-result)
* [IDA Pro plug-in tutorial](documentation/ida-pro-plugin.md#ida-pro-plug-in-tutorial)
  * [Functionalities](documentation/ida-pro-plugin.md#functionalities)
  * [Walk through example](documentation/ida-pro-plugin.md#walk-through-example)
    * [Preparing the data](documentation/ida-pro-plugin.md#preparing-the-data)
    * [Start the engine](documentation/ida-pro-plugin.md#start-the-engine)
    * [Indexing](documentation/ida-pro-plugin.md#indexing)
    * [Search and add comments](documentation/ida-pro-plugin.md#search-and-add-comments)
  * [How does the Plugin Work](documentation/ida-pro-plugin.md#how-does-the-plug-in-work)
    * [User Interface](documentation/ida-pro-plugin.md#user-interface)
    * [Synchronization](documentation/ida-pro-plugin.md#synchronization)
    * [Communication](documentation/ida-pro-plugin.md#communication)
* [Working with a cluster](documentation/cluster.md#working-with-a-cluster)
  * [Configure the Cassandra connection](documentation/cluster.md#configure-the-cassandra-connection)
  * [Configure the Spark connection](documentation/cluster.md#configure-the-spark-connection) 
* [Create your own processor definition](documentation/processor-definition.md#create-your-own-processor-definition)
* [Migrate repository from the previous version](documentation/migration.md#migrate-repository-from-the-previous-version)
* [CLI tutorial](documentation/CLI.md#cli-tutorial)

## Licensing

The software was developed by Steven H. H. Ding under the supervision of Benjamin C. M. Fung at the McGill Data Mining and Security Lab. Currently, we adopt a restrictive Creative Commons licensing model: Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0). In brief,

- Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- NonCommercial — You may not use the material for commercial purposes.
- NoDerivatives — If you remix, transform, or build upon the material, you may not distribute the modified material.

Please refer to License.txt for details. We will relax the licensing model after having some publications.

Copyright 2015 McGill Unviersity 
All rights reserved.
