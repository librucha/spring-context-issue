package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.client.ResourceAccessException;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

@Configuration
@EnableResourceServer
public class OAuth2ServerConfig extends ResourceServerConfigurerAdapter {

	public static final String RESOURCE_ID = "audanext-car";

	private String checkTokenEndpointUrl = "http://fakeurl.com";

	private String clientId = "client";

	private String clientSecret = "secret";

	private UserDetailsService userDetailsService = new InMemoryUserDetailsManager(singletonList(new User("user", "password", emptyList())));

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources
			 .resourceId(RESOURCE_ID)
			 .tokenServices(tokenServices());
	}

	@Bean
	@Profile("!stubbed")
	public ResourceServerTokenServices tokenServices() {
		RemoteTokenServices tokenServices = remoteTokenServices();
		tokenServices.setCheckTokenEndpointUrl(checkTokenEndpointUrl);
		tokenServices.setClientId(clientId);
		tokenServices.setClientSecret(clientSecret);
		tokenServices.setAccessTokenConverter(accessTokenConverter());
		return tokenServices;
	}

	private RemoteTokenServices remoteTokenServices() {
		return new RemoteTokenServices() {
			@Override
			public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
				try {
					return super.loadAuthentication(accessToken);
				} catch (ResourceAccessException e) {
					throw new RuntimeException("Exception", e);
				}
			}
		};
	}

	@Bean(name = "tokenServices")
	@Profile("stubbed")
	public ResourceServerTokenServices stubbedTokenServices(AccessTokenConverter accessTokenConverter) {
		return new ResourceServerTokenServices() {
			@Override
			public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
				requireNonNull(accessToken, "accessToken must not be null");
				Map<String, Object> response = new HashMap<>();
				response.put("aud", singletonList("audanext-car"));
				response.put("exp", Integer.MAX_VALUE);
				response.put("user_name", accessToken);
				response.put("client_id", "audanext-web");
				response.put("scope", singletonList("audanext-web-scope"));

				return accessTokenConverter.extractAuthentication(response);
			}

			@Override
			public OAuth2AccessToken readAccessToken(String accessToken) {
				throw new UnsupportedOperationException("Not supported: read access token");
			}
		};
	}

	@Bean
	public AccessTokenConverter accessTokenConverter() {
		DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(userTokenConverter());
		return accessTokenConverter;
	}

	@Bean
	public UserAuthenticationConverter userTokenConverter() {
		DefaultUserAuthenticationConverter userAuthenticationConverter = new DefaultUserAuthenticationConverter();
		userAuthenticationConverter.setUserDetailsService(userDetailsService);
		return userAuthenticationConverter;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
			 .authorizeRequests()
			 .anyRequest().authenticated();
	}
}
