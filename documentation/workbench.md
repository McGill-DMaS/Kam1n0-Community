# Kam1n0 Workbench Tutorial

* [Kam1n0 Workbench ](#kam1n0-workbench)
  * [Create a repository](#create-a-repository)
  * [Edit a repository](#edit-a-repository)
  * [Remove a repository](#remove-a-repository)
  * [Start or stop the Kam1n0 Engine](#start-or-stop-the-kam1n0-engine)
  * [JVM options for the Kam1n0 Engine](#jvm-options-for-the-kam1n0-engine)
  * [Moving a repository](#moving-a-repository)

# Kam1n0 Workbench

Kam1n0 Workbench is a user interface for managing multiple repositories as well as the running Kam1n0 instance. It is bundled with the installer for the core engine. After installing the Kam1n0 core engine, you could find its shortcut on your Start menu and desktop. 

![image](https://cloud.githubusercontent.com/assets/8474647/15004968/282b6896-118c-11e6-830b-0c40b7412471.png)

You could start the workbench by using these shortcuts. The main interface is shown as follows:

![image](https://cloud.githubusercontent.com/assets/8474647/15004978/4206e060-118c-11e6-8cbe-cba2e72341f1.png)

The main interface consists of three components: repository list, connector log, and engine log. Descriptions for each of them are given in the following table.

| Component | Description | Location |
|----------------|----------------|-------------|
|Repository list| Shows a list of repositories and their respective details| The upper table |
|Connector log| Display the logs of the workbench| The lower panel|
|Engine log| Display the logs of the running Kam1n0 engine|The lower panel|

Each repository shows its name, architecture, last access time, and directory in the upper table. The connector log shows the details about interacting with the Kam1n0 distribution on the computer. The engine log shows the logs of the running Kam1n0 service. 

With Kam1n0 workbench, a user can maintain multiple repositories on a workstation, start the Kam1n0 service with a selected repository, and stop the service. It is noted that only one Kam1n0 service can be running at a time on a given workstation. The Kam1n0 workbench will be minimized into a tray icon on the task bar. Double-clicking the tray icon will pop up the workbench again. Closing the workbench will shutdown the running Kam1n0 service. 

## Create a repository

It is simple to create a repository on your workstation. Click the `new` button below the repository list. You will see a new tab is added in the lower tab panel (as shown in the figure below).

![image](https://cloud.githubusercontent.com/assets/8474647/15005406/151c5138-1192-11e6-89ca-f9d83af8622e.png)

You need to pick a directory for this new repository. Make sure the Kam1n0 engine has the proper privilege to create files in that directory. All the data and configuration files of this repository will be stored at that location. Also, you need to choose a processor architecture from the drop down list. Lastly, please name the repository. Make sure the name is unique among the others in the repository list table.

After you create a repository, make sure to click the `save` button to persist the repository list on the hard drive. In the connector log tab you can see a new line is added: `changes saved`  (as shown in the figure below).

![image](https://cloud.githubusercontent.com/assets/8474647/15005475/1a1360ea-1193-11e6-9673-6783121d8c22.png)

The list of repository is stored at a folder name `Kam1n0` under your user directory.

## Edit a repository

To edit a repository, double click on any entry in the repository list table. A new tab is created in the same way you create a new repository. By editing any field in the newly created tab, you will see the same changes applied to the repository list.  Remember to click the `save` button after you finish editing.

![image](https://cloud.githubusercontent.com/assets/8474647/15005622/0ab7206c-1195-11e6-87b8-dda70bad7828.png)


It is noted that the chosen architecture of a repository in workbench will only be used to create the repository. If you want to really change the processor architecture of a given repository, you need to change the configuration file under the directory of that directory for the changes to take effect. It is not recommended to change this option once a repository is created. 

# Remove a repository

To remove a specific repository, select it from the repository list table and click the `delete` button. After the changes, make sure you click the `save` button. It is noted that removing a repository from the list does not remove the actual repository on your hard drive. It is still there and you can add it back using the same procedure above to create a new repository. The Kam1n0 engine will automatically recognize that it is an existing repository. To permanently delete a repository, you need to remove its directory manually. 

# Start or stop the Kam1n0 Engine

To start the engine, you need to pick one of the repository from the upper table and then click on the `Start` button. You will see that the Engine log tab in the lower tab panel being automatically activated and the engine starts running. The repository table will be disabled when you run the engine because only one engine is allowed to run at a time on a workstation. 

![image](https://cloud.githubusercontent.com/assets/8474647/15005707/ff95ff2c-1195-11e6-84e2-e68a7c1e6dfb.png)

If the chosen repository is a new repository, Kam1n0 engine will initialize the repository's directory with the necessary data and configuration files; otherwise, Kam1n0 will run the service according to the existing configuration file. Default configurations can be found in the Kam1n0's installation directory.

If your browser pops up a login page like the one below. The engine is running good. The default username and password are both `admin`. Usually it takes a couple seconds to start up the engine.

![image](https://cloud.githubusercontent.com/assets/8474647/15005811/631c4f46-1197-11e6-843d-d79c84c12a18.png)

To shutdown the engine, click the stop button on the workbench UI. Alternatively, you could close the workbench and it will shutdown the engine before exiting. 

## JVM options for the Kam1n0 Engine

You can edit the JVM options for the Kam1n0 engine by clicking the menu bar item `Edit` and the entry `JVM Options` under the sub-menu. A new tab is created for you to modify the JVM option. Options are separated by lines. Click the `save` button on the newly created tab to persists the JVM option.

## Moving a repository

After moving a repository to another directory, you need to manually update the following configurations:

* [Workbench] update the directory of the moved repository and click the `save button`.
* [kam1n0-conf.xml under the repository's directory] update the `dataPath` entry to the new location.
* [log4j2.xml  under the repository's directory] update the `fileName` entry under the `File` tag to a file under your new directory.

If you move a repository to a different workstation, make sure you also update the `idaHome` entry in file `kam1n0-conf.xml` to the IDA Pro installation location on the new workstation.



