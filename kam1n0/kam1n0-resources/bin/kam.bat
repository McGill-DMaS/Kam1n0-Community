@rem ***************************************************************************
@rem Copyright 2015 McGill University. All rights reserved.                       
@rem                                                                               
@rem Unless required by applicable law or agreed to in writing, the software      
@rem is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF      
@rem ANY KIND, either express or implied.                                         
@rem ***************************************************************************
@echo off

set "opts="
For /F "tokens=1* delims==" %%A IN (%~dp0kam1n0.properties) DO (
    IF "%%A"=="jvm-option" (
    	call set "opts=%%opts%% %%B"
    )
)
set EDIR="%~dp0kam1n0-server.jar%"
echo java %opts% -jar %EDIR% %*% 
java %opts% -jar %EDIR% %*% 