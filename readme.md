<pre>
    _________                        __                  
    \_   ___ \_______   ____ _____ _/  |_  ____          
    /    \  \/\_  __ \_/ __ \\__  \\   __\/ __ \         
    \     \____|  | \/\  ___/ / __ \|  | \  ___/         
     \______  /|__|    \___  >____  /__|  \___  >        
            \/             \/     \/          \/         
 __________                                              
 \______   \_______  ____   ____  ____   ______ ______   
  |     ___/\_  __ \/  _ \_/ ___\/ __ \ /  ___//  ___/   
  |    |     |  | \(  <_> )  \__\  ___/ \___ \ \___ \    
  |____|     |__|   \____/ \___  >___  >____  >____  >   
                               \/    \/     \/     \/    
 _______          __  .__  _____       ___________       
 \      \   _____/  |_|__|/ ____\__.__.\_   _____/__  ___
 /   |   \ /  _ \   __\  \   __<   |  | |    __)_\  \/  /
/    |    (  <_> )  | |  ||  |  \___  | |        \>    < 
\____|__  /\____/|__| |__||__|  / ____|/_______  /__/\_ \
        \/                      \/             \/      \/
       ________        .__                               
       \______ \_______|__|__  __ ___________            
        |    |  \_  __ \  \  \/ // __ \_  __ \           
        |    `   \  | \/  |\   /\  ___/|  | \/           
       /_______  /__|  |__| \_/  \___  >__|              
               \/                    \/      


LICENSE
~~~~~~~

Copyright (c) 2018-2022 Florian Rienhardt (hazelfazel@bitnuts.de)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


ABSTRACT
~~~~~~~~

Sample driver demonstrating how to implement a simple, kernel-only process and command line
monitoring driver for Microsoft Windows.

The driver registers a callback routine to be called whenever a process is
created or deleted. This driver can be used for process creation monitoring. You
can easily expand the driver to also block process creation attempts for specific
parents invoking new processes. This might help to mitigate against typical
attacks origination from office, browser and media playing tools. E.g. ask yourself
"why should my text editor, pdf viewer or browser start cmd.exe or powershell.exe"?
	
Please note, there exist techniques to bypass such process monitoring (in-memory
attempts, reflective code loading). Hence, such a driver can only be _one_ part
of a monitoring	and mitigation strategy. There is no claim to be bullet-proof!


How to install and use
~~~~~~~~~~~~~~~~~~~~~~

To install the driver, just go into the binaries path regarding your architecture of Windows.
Then right-select the .inf and hit "install". You can use one of the cmd-scripts to start,
stop, restart and uninstall the driver. The scripts are located in the project's root folder.


Logging
~~~~~~~

The driver logs events to %windir%\CreateProcessNotifyEx.log
</pre>
