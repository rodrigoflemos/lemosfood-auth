package br.com.lemos.lemosfood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
//	@Autowired
//	private RedisConnectionFactory redisConnectionFactory;
		
	//Configura os detalhes dos clients 
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("lemosfood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password","refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60)
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60)
			
			.and()//http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://aplicacao-cliente
			
			/* Com PKCE plain: 
			 * 
			 * Code Verifier: teste123
			 * Code Challenge: teste123 
			 * 
			 * http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics
			&redirect_uri=http://aplicacao-cliente&code_challenge=teste123&code_challenge_method=plain
			
			* Com PKCE sha256: 
			* 
			* Code Verifier: teste123
			* Code Challenge: base64url((sha256("teste123"))) = KJFg2w2fOfmuF1TE7JwW-QtQ4y4JxftUga5kKz09GjY
			* 
			* http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics
			&redirect_uri=http://aplicacao-cliente&code_challenge=KJFg2w2fOfmuF1TE7JwW-QtQ4y4JxftUga5kKz09GjY&code_challenge_method=s256
			*
			*/

				.withClient("foodanalytics")
				.secret(passwordEncoder.encode(""))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
				
			.and()//http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente")
				
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read")
				
			.and()
				.withClient("checktoken")
				.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()")
			.allowFormAuthenticationForClients();
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAccessTokenConverter())
			.tokenGranter(tokenGranter(endpoints));// Gera um novo refresh token cada vez que o refresh token for utilizado
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter () {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAccessTokenConverter.setSigningKey("as9d879sdf7asdf78a9dsadf87987fd89s87fs9a987s98f");
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
}