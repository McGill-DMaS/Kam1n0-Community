package ca.mcgill.sis.dmas.kam1n0.app.user;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class UserInfoWrapper extends User {

	private static final long serialVersionUID = -3558201935290633278L;
	public UserInfo entity;

	public UserInfoWrapper(String username, String password, Collection<? extends GrantedAuthority> authorities,
			UserInfo userEntiy) {
		super(username, password, authorities);
		this.entity = userEntiy;
	}

}
