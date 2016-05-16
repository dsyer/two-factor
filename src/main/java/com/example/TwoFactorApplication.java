package com.example;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@SpringBootApplication
public class TwoFactorApplication extends WebSecurityConfigurerAdapter {

	private final RequestCache requestCache;

	public TwoFactorApplication(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

	@Configuration
	protected static class RequestCacheConfiguration {
		@Bean
		public RequestCache savedRequestCache() {
			return new HttpSessionRequestCache() {
				@Override
				public void removeRequest(HttpServletRequest currentRequest,
						HttpServletResponse response) {
					Authentication authentication = SecurityContextHolder.getContext()
							.getAuthentication();
					if (authentication != null && authentication.getAuthorities()
							.contains(new SimpleGrantedAuthority("ROLE_FACTOR"))) {
						super.removeRequest(currentRequest, response);
					}
				}
			};
		}
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.requestCache().requestCache(requestCache).and().formLogin()
				.loginPage("/login").permitAll().and().logout().permitAll().and()
				.exceptionHandling().accessDeniedHandler(accessDeniedHandler()).and()
				.authorizeRequests().antMatchers("/factor/**").authenticated()
				.anyRequest().hasRole("FACTOR");
	}

	private AccessDeniedHandler accessDeniedHandler() {
		return new AccessDeniedHandlerImpl() {
			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException)
					throws IOException, ServletException {
				Authentication authentication = SecurityContextHolder.getContext()
						.getAuthentication();
				if (authentication != null && !authentication.getAuthorities()
						.contains(new SimpleGrantedAuthority("ROLE_TWO_FACTOR"))) {
					RequestDispatcher dispatcher = request
							.getRequestDispatcher("/factor");
					dispatcher.forward(request, response);
				}
				super.handle(request, response, accessDeniedException);
			}
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(TwoFactorApplication.class, args);
	}
}
