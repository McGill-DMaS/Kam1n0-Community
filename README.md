#  ![image](https://cloud.githubusercontent.com/assets/8474647/14999349/a530f954-1156-11e6-8d8b-6b2136c322bb.png) What Is Kam1n0?

Assembly code analysis is a time-consuming process. An effective and efficient assembly code clone search engine can greatly reduce the effort of this process, since it can identify the cloned parts that have been previously analyzed. Kam1n0 is a scalable system that supports assembly code clone search. It allows a user to first index a (large) collection of binaries, and then search for the code clones of a given target function or binary file. 

Kam1n0 tries to solve the efficient subgraph search problem (i.e. graph isomorphism problem) for assembly functions. Given a target function (the middle one in the figure below) it can identity the cloned subgraphs among other functions in the repository (the ones on the left and the right as shown below). Kam1n0 supports rich comment format and has an IDA Pro plug-in to use its indexing and searching capabilities via IDA Pro. 

Kam1n0 was developed by Steven H. H. Ding under the supervision of Benjamin C. M. Fung in the [Data Mining and Security Lab](http://dmas.lab.mcgill.ca/) at McGill University in Canada. This software won the second prize in the [Hex-Rays Plug-In Contest 2015](https://hex-rays.com/contests/2015/).

![image](https://cloud.githubusercontent.com/assets/8474647/9867360/a130631c-5b3a-11e5-8b76-83afec582886.png)

In this repository we release the initial version of Kam1n0 and its IDA Pro plug-in. It can run on a single workstation/server, and provides clone search service through RESTful web services. The users can connect to the server through IDA Pro. Alternatively, it can be deployed on a distributed cluster (next major release).

## Latest Release Note

###  2016-05-03 1.0.0-rc1

#### Changes:

* [Web UI] Added a web interface for clone search of assembly function.
* [Web UI] Added a web interface for clone search of whole binary file.
* [Kam1n0 Workbench] Added a Kam1n0 workbench to create and manage multiple repositories on a single workstation.
* [Kam1n0 Core] The binary file clone search result can be shared and browsed on the other machine without access to the repository.
* [Kam1n0 Core] Support indexing and searching for large binary file (>40mb) without limits on system memory.
* [Kam1n0 Core] Support ARM, PowerPC, x86 and amd86 binaries.
* [Kam1n0 Core] Support user-defined processor architecture.
* [Kam1n0 Core] Optimized index structure supports better scalability and clone search quality.
* [Kam1n0 Core] Kam1n0 no longer skips basic blocks which have less than three lines of instruction. Now only single line basic block is skipped; thanks to the new index structure.
* [IDA Pro plug-in for Kam1n0] Added assembly fragment search functionality. 
* [IDA Pro plug-in for Kam1n0] Added a tree view for browsing large number of clones.

#### Compatibility:

* The repositories and configuration files used in previous versions are no longer supported by the latest version.

## Documentation

* [Installation](#installation)
* [Manage Repositories with Kam1n0 Workbench](#manage-repositories)
* [Web Interface Tutorial](#web-interface-tutorial)
* [IDA Pro Plug-in Tutorial](#ida-pro-plugin-tutorial)
* [Create Your Own Processor Definition](#create-your-own-processor-definition)
* [Migrate Repository from Previous Version](#migrate-repository)

## Licensing

The software was developed by Steven H. H. Ding under the supervision of Benjamin C. M. Fung at the McGill Data Mining and Security Lab. Currently, we adopt a restrictive Creative Commons licensing model: Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0). In brief,

- Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- NonCommercial — You may not use the material for commercial purposes.
- NoDerivatives — If you remix, transform, or build upon the material, you may not distribute the modified material.

Please refer to License.txt for details. We will relax the licensing model after having some publications.

Copyright 2015 McGill Unviersity 
All rights reserved.
