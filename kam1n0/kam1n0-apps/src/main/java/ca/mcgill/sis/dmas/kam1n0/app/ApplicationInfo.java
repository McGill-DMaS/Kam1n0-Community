package ca.mcgill.sis.dmas.kam1n0.app;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBasic;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBytes;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsString;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedPrimary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;

public class ApplicationInfo implements Serializable {

	private static final long serialVersionUID = 5942792596770822452L;

	@KeyedPrimary
	public long appId = -1;

	@AsBasic
	public Set<String> users_read = new HashSet<>();

	@AsBasic
	public Set<String> users_wirte = new HashSet<>();

	@AsBasic
	public Set<String> users_owners = new HashSet<>();

	@AsString
	public ApplicationConfiguration configuration = new ApplicationConfiguration();

	public long getAppId() {
		return appId;
	}

	public void setAppId(long appId) {
		this.appId = appId;
	}

	public ApplicationConfiguration getConfiguration() {
		return configuration;
	}

	public Set<String> getUsers_read() {
		return users_read;
	}

	public void setUsers_read(Set<String> users_read) {
		this.users_read = users_read;
	}

	public Set<String> getUsers_wirte() {
		return users_wirte;
	}

	public void setUsers_wirte(Set<String> users_wirte) {
		this.users_wirte = users_wirte;
	}

	public Set<String> getUsers_owners() {
		return users_owners;
	}

	public void setUsers_owners(Set<String> users_owners) {
		this.users_owners = users_owners;
	}

	public void setConfiguration(ApplicationConfiguration configuration) {
		this.configuration = configuration;
	}

	public boolean getIsPrivate() {
		return isPrivate;
	}

	public void setIsPrivate(boolean isPrivate) {
		this.isPrivate = isPrivate;
	}

	public String getApplicationType() {
		return applicationType;
	}

	public void setApplicationType(String applicationType) {
		this.applicationType = applicationType;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Boolean isPrivate = false;

	public Boolean isOnline = true;

	public String applicationType;

	public String title;

	public String name;

	public String description;

	public String owner;

	public String getOwner() {
		return owner;
	}

	public void setOwner(String owner) {
		this.owner = owner;
	}

	@AsString
	public Date creationDate = new Date();

	public Date getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	public Boolean getIsOnline() {
		return isOnline;
	}

	public void setIsOnline(Boolean isOnline) {
		this.isOnline = isOnline;
	}

	public void setIsPrivate(Boolean isPrivate) {
		this.isPrivate = isPrivate;
	}

	public String calculatePrefix() {
		return ApplicationHandler.getPrefixPath(this.applicationType, this.appId);
	}

}
