## Full build scripts for Kam1n0 under different platform. 
Scripts should be executed in the following sequence:

* build-vex.bat   
  * renew vex distribution
  * copy binaries to /kam1n0/kam1n0-resources/bin/lib
* build-z3.bat    
  * renew z3 distribution
  * intall z3 to local m2 repo
  * copy binaries to /kam1n0/kam1n0-resources/bin/lib
* build-distribution.bat	
  * compile java code and merge resources into /kam1n0/build-bins/
* build-installers.bat
  * pakcage platform-specific binaries.
  * should only depend on /kam1n0/build-bins/ and /kam1n0-clientss/
