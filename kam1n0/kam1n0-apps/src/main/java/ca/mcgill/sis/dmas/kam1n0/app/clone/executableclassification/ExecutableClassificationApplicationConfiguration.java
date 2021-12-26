package ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification;


import java.util.ArrayList;
import java.util.Arrays;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;

@AppType(ExecutableClassificationApplicationMeta.appType)
public class ExecutableClassificationApplicationConfiguration extends ApplicationConfiguration {
	public int getIteration() {
		return iteration;
	}

	public void setIteration(int iteration) {
		this.iteration = iteration;
	}

	public int getNegative_samples() {
		return negative_samples;
	}

	public void setNegative_samples(int negative_samples) {
		this.negative_samples = negative_samples;
	}

	public int getMin_frequeceny() {
		return min_frequeceny;
	}

	public void setMin_frequeceny(int min_frequeceny) {
		this.min_frequeceny = min_frequeceny;
	}

	public int getDim() {
		return dim;
	}

	public void setDim(int dim) {
		this.dim = dim;
	}

	public ArrayList<String> getClasses() {
		return classes;
	}

	public void setClasses(ArrayList<String> classes) {
        if(classes.size()>1)
		    this.classes = classes;
        else
        {
		    String mother = classes.get(0).replaceAll("\\r\\n", ",").replaceAll("\\r", ",").replaceAll("\\n", ",").replaceAll(" ", ",");
	    	String[] parts = mother.split(",");
	    	this.classes = new ArrayList<String>(Arrays.asList(parts));
	    	for(int i=0; i < this.classes.size(); i++)
	    	{
	    		this.classes.set(i,this.classes.get(i).replaceAll("\\r\\n", "").replaceAll("\\r", "").replaceAll("\\n", "").replaceAll(" ", ""));
	    	}
        }

	}
	public static enum ClusterModel {
		union,slink;
	}
	
	
	public double getSimilarity_threshold_for_cluster() {
		return similarity_threshold_for_cluster;
	}

	public void setSimilarity_threshold_for_cluster(double similarity_threshold_for_cluster) {
		this.similarity_threshold_for_cluster = similarity_threshold_for_cluster;
	}
	
	


	public double getCluster_class_distribution_significance() {
		return cluster_class_distribution_significance;
	}

	public void setCluster_class_distribution_significance(double cluster_class_distribution_significance) {
		this.cluster_class_distribution_significance = cluster_class_distribution_significance;
	}

	public int getMin_exe_per_cluster() {
		return min_exe_per_cluster;
	}

	public void setMin_exe_per_cluster(int min_exe_per_cluster) {
		this.min_exe_per_cluster = min_exe_per_cluster;
	}

	private static final long serialVersionUID = -2906612746988442788L;

	public ArchitectureType architectureType = ArchitectureType.metapc;
	public ClusterModel clusterModel = ClusterModel.union;
	public int kStart = 4;
	public int kMax = 128;
	public int mSplit = 100;
	public int l = 15;

	public int iteration = 20;
	public int negative_samples = 25;
	public int min_frequeceny = 1;
	public int dim = 100;
	public double similarity_threshold_for_cluster = 0.85;
	public double cluster_class_distribution_significance = 0.4;
	public int min_exe_per_cluster = 2;
	
	public ArrayList<String> classes;

	public Asm2VecNewParam convertToParam() {
		Asm2VecNewParam param = new Asm2VecNewParam();
		param.optm_iteration = iteration;
		param.optm_negSample = negative_samples;
		param.min_freq = min_frequeceny;
		param.vec_dim = dim;
		return param;
	}
	
	

	@Override
	public String createView() {
		return "apps/clone" + ExecutableClassificationApplicationMeta.appType + "/confg";
	}

	@Override
	public String createFragEdit() {
		return "apps/clone" + ExecutableClassificationApplicationMeta.appType + "/confg";
	}

	public ArchitectureType getArchitectureType() {
		return architectureType;
	}

	public void setArchitectureType(ArchitectureType architectureType) {
		this.architectureType = architectureType;
	}

	public int getkStart() {
		return kStart;
	}

	public void setkStart(int kStart) {
		this.kStart = kStart;
	}

	public int getkMax() {
		return kMax;
	}

	public void setkMax(int kMax) {
		this.kMax = kMax;
	}

	public int getmSplit() {
		return mSplit;
	}

	public ClusterModel getClusterModel() {
		return clusterModel;
	}

	public void setClusterModel(ClusterModel clusterModel) {
		this.clusterModel = clusterModel;
	}

	public void setmSplit(int mSplit) {
		this.mSplit = mSplit;
	}

	public int getL() {
		return l;
	}

	public void setL(int l) {
		this.l = l;
	}
}
