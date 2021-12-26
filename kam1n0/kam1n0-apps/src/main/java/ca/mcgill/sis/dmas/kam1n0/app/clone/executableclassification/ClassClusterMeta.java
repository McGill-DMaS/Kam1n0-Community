package ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class ClassClusterMeta implements Serializable {


	@KeyedSecondary
	public String className;

	@AsString
	public Set<String> classClusterList;

	public ClassClusterMeta(String class_name) {
		super();
		this.className = class_name;
		this.classClusterList = new HashSet<String>();
	}

	public ClassClusterMeta() {
		this.className = "";
		this.classClusterList =  new HashSet<String>();
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}

	public Set<String> getClassBinaryList() {
		return classClusterList;
	}

	public void setClassBinaryList(Set<String> classClusterList) {
		this.classClusterList = classClusterList;
	}
	


	
}
