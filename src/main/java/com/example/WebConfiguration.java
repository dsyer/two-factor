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

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.ui.ModelMap;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * @author Dave Syer
 *
 */
@Configuration
public class WebConfiguration extends WebMvcConfigurerAdapter {

	private ServerProperties server;

	public WebConfiguration(ServerProperties server) {
		this.server = server;
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addWebRequestInterceptor(interceptor());
	}

	private WebRequestInterceptor interceptor() {
		return new WebRequestInterceptor() {

			@Override
			public void preHandle(WebRequest request) throws Exception {
			}

			@Override
			public void postHandle(WebRequest request, ModelMap model) throws Exception {
				if (model == null) {
					return;
				}
				if (request.getAttribute("contextPath",
						WebRequest.SCOPE_REQUEST) == null) {
					model.put("contextPath", server.getContextPath() == null ? ""
							: server.getContextPath());
				}
				else {
					// Slightly bizarre. Prevents error in template view when forwarding
					// to a view with the user already present.
					model.remove("user");
				}
			}

			@Override
			public void afterCompletion(WebRequest request, Exception ex)
					throws Exception {
			}
		};
	}
}
