# Working with a cluster

Make sure you have properly setup the cluster with Spark and Cassandra. Spark and Cassandra can run on the same cluster. In order to have Kam1n0 engine work with on a cluster, firstly you need to create a local repository using Kam1n0 workbench. After that, start the Kam1n0 engine. Let it initialize the configuration files for the newly created repository. You will find the configuration file `kam1n0-conf.xml` under its directory. Shutdown the engine, and modify the configuration file as follows:

### Configure the Cassandra connection
Locate the `<cassandra>` xml tag. It contains necessary information about the Cassandra connector. 

```xml
<cassandra>
    <host>$host$</host>
    <port>9042</port>
    <portStorage>7000</portStorage>
    <embedded>true</embedded>
  </cassandra>
```

* `<host>` tag: the remote host name or IP address of the Cassandra cluster. It will not be used by the embeded Cassandra instance.
* `<port>` tag: the remote port of the Cassandra cluster. It also will be used as local port by the embeded Cassandra instance.
* `<portStorage>` tag: the port used for Cassandra iternal communication.
* `<embedded>` tag: a boolean value which indicates whether Kam1n0 should use an embeded Cassandra database locally or connect to a remote Cassandra cluster.

### Configure the Spark connection
Locate the `<spark>` xml tag. It contains necessary information about the Spark connector. 

```xml
<spark>
    <embedded>true</embedded>
    <showWebUI>true</showWebUI>
    <webUIPort>4040</webUIPort>
    <localModeCores>4</localModeCores>
    <remoteModeHost>remoteModeHost</remoteModeHost>
    <remoteModeMemForExecutor>4g</remoteModeMemForExecutor>
    <remoteModeDriverPort>7077</remoteModeDriverPort>
  </spark>
```

* `<embedded>` tag: a boolean value which indicates whether Kam1n0 should use an embeded Spark instance locally or connect to a remote Spark cluster.
* `<showWebUI>` tag: whether to disable the web UI for Spark. The URL is `http://127.0.0.1:webUIPort`.
* `<webUIPort>` tag: the port number for the Spark web UI.
* `<localModeCores>` tag: number of cores to be used in local mode. This value will not be used if Kam1n0 connects to a remote Spark cluster.
* `<remoteModeHost>` tag: the remote host name or IP address of the Spark cluster. It will not be used by the embeded Spark instance.
* `<remoteModeMemForExecutor>` tag: the size of memory allocated for Kam1n0 on each executors of the remote Spark cluster.
* `<remoteModeDriverPort>` tag: the port number of the remote Spark cluster.
