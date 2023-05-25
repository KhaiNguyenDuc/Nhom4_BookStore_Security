package com.metis.book.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

import com.metis.book.security.oauth.CustomOauth2UserService;
import com.metis.book.security.oauth.OAuthLoginFailureHandler;
import com.metis.book.security.oauth.OAuthLoginSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	String[] allowURL = {
			"/static/**",
            "/auth/**",
            "/oauth2/**",
            "/uploads/categories/**",
            "/uploads/blogs/**",
            "/uploads/books/**"
            };
	String [] allowURLAdmin = {
			"/uploads/users/1.png",
            "/uploads/**"
	};
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.cors()
				.disable()
			.formLogin()
				.usernameParameter("email")
				.loginPage("/auth/login")
				.loginProcessingUrl("/auth/login")
				.successHandler(myLoginSuccessHandler())
				.failureHandler(myLoginFailureHandler())
			.and()
				.requestCache().requestCache(requestCache())
			.and()
				.logout()
				.logoutUrl("/auth/logout")
				.logoutSuccessUrl("/")
				.deleteCookies("JSESSIONID","remember-me")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
			.and()
				.oauth2Login()
					.loginPage("/auth/login")
					.successHandler(myOAuthLoginSuccessHandler())
					.failureHandler(myOAuthLoginFailureHandler())
					.userInfoEndpoint()
						.userService(auth2UserService())
				.and()
			.and()
				.rememberMe()
				.tokenValiditySeconds(1209600) // 14 days
			.and()
				.authorizeRequests()
					.antMatchers(allowURL)
						.permitAll()
					.antMatchers(allowURLAdmin)
						.hasAuthority("ROLE_ADMIN")
					.antMatchers("/member/**")
						.hasAuthority("ROLE_USER")
					.antMatchers("/admin/user/**")
						.hasAuthority("ROLE_ADMIN")
					.antMatchers("/admin/**")
						.hasAnyAuthority("ROLE_ADMIN","ROLE_STAFF")
					.anyRequest()
						.permitAll();
		http.headers()
				.xssProtection()
			.and()
				.contentSecurityPolicy("trusted-cdn.com; frame-ancestors 'self'; form-action 'self'");
		return http.build();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	AuthenticationSuccessHandler myLoginSuccessHandler(){
	    return new LoginSuccessHandler();
	}
	
	@Bean
	AuthenticationFailureHandler myLoginFailureHandler() {
		return new LoginFailureHandler();
	}
	@Bean
	OAuthLoginFailureHandler myOAuthLoginFailureHandler() {
		return new OAuthLoginFailureHandler();
	}
	
	@Bean
	OAuthLoginSuccessHandler myOAuthLoginSuccessHandler() {
		return new OAuthLoginSuccessHandler();
	}
	
	@Bean 
	DefaultOAuth2UserService auth2UserService() {
		return new CustomOauth2UserService();
	}
	
	@Bean
	RequestCache requestCache() {
	   return new HttpSessionRequestCache();
	}

}
