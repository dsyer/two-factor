/*
 * Copyright 2013-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Dave Syer
 *
 */
@Controller
public class AuthenticationController {

	private SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();

	public AuthenticationController(RequestCache requestCache) {
		handler.setRequestCache(requestCache);
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/factor")
	public String factor(@RequestParam(required = false) String error,
			Map<String, Object> model) {
		if (error != null) {
			model.put("error", error);
		}
		return "factor";
	}

	@PostMapping("/factor")
	public void accept(@RequestParam String factor, Principal principal,
			HttpServletRequest request, HttpServletResponse response) throws Exception {
		if (!"red".equals(factor)) {
			response.sendRedirect("/factor?error=true");
			return;
		}
		Authentication authentication = (Authentication) principal;
		Collection<GrantedAuthority> authorities = new ArrayList<>(
				authentication.getAuthorities());
		authorities.add(new SimpleGrantedAuthority("ROLE_FACTOR"));
		PreAuthenticatedAuthenticationToken successful = new PreAuthenticatedAuthenticationToken(
				authentication.getPrincipal(), authentication.getCredentials(),
				authorities);
		successful.setDetails(authentication.getDetails());
		SecurityContextHolder.getContext().setAuthentication(successful);
		handler.onAuthenticationSuccess(request, response, successful);
	}

}
