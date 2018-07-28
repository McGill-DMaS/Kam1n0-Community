package ca.mcgill.sis.dmas.kam1n0;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import ca.mcgill.sis.dmas.kam1n0.app.user.UserFactory.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()//
				.antMatchers(//
						"/", //
						"/index.html", //
						"/login", //
						"/register", //
						"/public/**", //
						"/data/**", //
						"/js/**", //
						"/css/**", //
						"/css-external/**",//
						"/img/**", //
						"/material-kit/assets/**"//
				).permitAll()//
				.anyRequest().authenticated()//
				.and()//
				.formLogin()//
				.loginPage("/login")//
				.defaultSuccessUrl("/userHome", true)//
				.permitAll()//
				.and()//
				.logout()//
				.permitAll();//
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
	}
}