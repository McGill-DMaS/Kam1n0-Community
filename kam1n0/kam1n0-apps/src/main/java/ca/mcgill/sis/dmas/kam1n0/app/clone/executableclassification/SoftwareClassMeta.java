package ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class SoftwareClassMeta implements Serializable {


	@KeyedSecondary
	public String className;

	@AsString
	public Set<Long> classBinaryList;

	@AsString
	public Set<String> classClusterList;
	
	public double averageNCluster;

	public SoftwareClassMeta(String class_name) {
		super();
		this.className = class_name;
		this.averageNCluster = 0;
		this.classBinaryList = new HashSet<Long>();
		this.classClusterList = new HashSet<String>();
	}

	public SoftwareClassMeta() {
		this.className = null;
		this.averageNCluster = 0;
		this.classBinaryList = null;
		this.classClusterList = null;
	}

	public double getAverageNCluster() {
		return averageNCluster;
	}

	public void setAverageNCluster(float averageNCluster) {
		this.averageNCluster = averageNCluster;
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}

	public Set<Long> getClassBinaryList() {
		return classBinaryList;
	}

	public void setClassBinaryList(Set<Long> classBinaryList) {
		this.classBinaryList = classBinaryList;
	}
	

	public Set<String> getClassClusterList() {
		return classClusterList;
	}

	public void setClassClusterList(Set<String> classClusterList) {
		this.classClusterList = classClusterList;
	}

	
}
