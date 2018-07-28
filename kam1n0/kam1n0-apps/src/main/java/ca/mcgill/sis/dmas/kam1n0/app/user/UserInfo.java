package ca.mcgill.sis.dmas.kam1n0.app.user;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBytes;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedPrimary;
import scala.Tuple2;

public class UserInfo implements Serializable {

	private static final long serialVersionUID = 7882203846042062070L;

	public transient boolean aggreeTLicense = false;

	public boolean isAggreeTLicense() {
		return aggreeTLicense;
	}

	public void setAggreeTLicense(boolean aggreeTLicense) {
		this.aggreeTLicense = aggreeTLicense;
	}

	@KeyedPrimary
	public String userName = StringResources.STR_EMPTY;

	public String email = StringResources.STR_EMPTY;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getCredential() {
		return credential;
	}

	public void setCredential(String credential) {
		this.credential = credential;
	}

	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles;
	}

	public Set<Long> getOwnedApps() {
		return ownedApps;
	}

	public void setOwnedApps(Set<Long> ownedApps) {
		this.ownedApps = ownedApps;
	}

	public String credential = StringResources.STR_EMPTY;

	public Set<String> roles = new HashSet<>();

	@AsString
	public Set<Long> ownedApps = new HashSet<>();

	@AsString
	public Set<Long> accessibleApps = new HashSet<>();
}
