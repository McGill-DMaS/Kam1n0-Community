@rem ***************************************************************************
@rem Copyright 2015 McGill University. All rights reserved.                       
@rem                                                                               
@rem Unless required by applicable law or agreed to in writing, the software      
@rem is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF      
@rem ANY KIND, either express or implied.                                         
@rem ***************************************************************************
@echo off
set ADIR="%~dp0\jamm-0.2.5.jar"%
set EDIR="%~dp0\Kam1n0-0.1.0.jar"%*
java -javaagent:%ADIR% -Dlog4j.configurationFile=file:"C:\ding\IDA 6.7\plugins\Kam1n0WinSetupProject\Kam1n0WinSetupProject\bin_release\Kam1n0-distribution\log4j2.xml" -jar %EDIR%