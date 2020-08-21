package br.com.lemos.lemosfood.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	
		//Configura usuario em memoria
		
		auth.inMemoryAuthentication()
			.withUser("rodrigo")
				.password(passwordEncoder().encode("123456"))
				.roles("ADMIN")
			.and()
			.withUser("joao")
				.password(passwordEncoder().encode("123"))
				.roles("ADMIN");
	}
	
	//Bean registrado para que a configuracao de usuario em memoria funcione. Caso nao seja registrado ocorre uma exception apontando id null
	@Bean
	public PasswordEncoder passwordEncoder () {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
}