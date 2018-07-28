package ca.mcgill.sis.dmas.kam1n0.app.user;

import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;

import java.io.Serializable;
import java.util.List;

public class UserEntity implements Serializable {
	private static final long serialVersionUID = 8158847125183734602L;
	public UserInfo info;
	public List<ApplicationInfo> recentApps;

	public UserEntity(UserInfo info, List<ApplicationInfo> recentApps) {
		this.info = info;
		this.recentApps = recentApps;
	}
}
