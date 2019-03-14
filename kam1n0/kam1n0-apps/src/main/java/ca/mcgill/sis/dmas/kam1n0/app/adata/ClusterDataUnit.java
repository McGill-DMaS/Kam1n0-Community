package ca.mcgill.sis.dmas.kam1n0.app.adata;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;

public class ClusterDataUnit {

	public String clusterName;
	public String numFunctions;

	public ClusterDataUnit(Cluster cluster) {
		clusterName = cluster.clusterName;
		numFunctions = Integer.toString(cluster.functionIDList.size());
	}

}
