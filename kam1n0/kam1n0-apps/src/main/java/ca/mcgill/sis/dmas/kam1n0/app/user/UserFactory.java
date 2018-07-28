package ca.mcgill.sis.dmas.kam1n0.app.user;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import ca.mcgill.sis.dmas.kam1n0.GlobalResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Component
public class UserFactory {

	public final static String SYS_USER_NAME_IDA = "user_ida";

	private static Logger logger = LoggerFactory.getLogger(UserFactory.class);
	private ObjectFactoryMultiTenancy<UserInfo> userFactory;
	private Long global_key = -1l;
	public static final String ROLE_USER = "R_USER";
	public static final String ROLE_ADMN = "R_ADMIN";

	public void prioritize() {
		userFactory.prioritize();
	}

	@Autowired
	public UserFactory(GlobalResources res) {
		try {
			global_key = res.global_key;
			userFactory = new ObjectFactoryCassandra<UserInfo>(res.cassandra, res.spark);
			userFactory.init(res.platform_name, res.global_name, UserInfo.class);
		} catch (Exception e) {
			logger.error("Failed to initialize component " + this.getClass().getName());
		}
	}

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public void save(UserInfo user) {
		userFactory.put(global_key, user);
	}

	public void add(UserInfo user) {
		user.credential = bCryptPasswordEncoder.encode(user.credential);
		user.roles.add(ROLE_USER);
		userFactory.put(global_key, user);
	}

	public void update(UserInfo user) {
		userFactory.put(global_key, user);
	}

	public UserInfo findUser(String userName) {
		UserInfo info = userFactory.querySingle(global_key, userName);
		return info;
	}

	public List<UserInfo> findUser(Collection<String> userNames) {
		List<UserInfo> info = userFactory.queryMultiple(global_key, "userName", userNames).collect();
		return info;
	}

	@Service
	public static class UserDetailsServiceImpl implements UserDetailsService {
		@Autowired
		private UserFactory factory;

		@Override
		public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
			factory.prioritize();
			UserInfo user = factory.findUser(userName);
			if (user == null)
				throw new UsernameNotFoundException("user not found. ");

			Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
			for (String role : user.roles) {
				grantedAuthorities.add(new SimpleGrantedAuthority(role));
			}
			return new UserInfoWrapper(user.userName, user.credential, grantedAuthorities, user);
		}
	}
}
