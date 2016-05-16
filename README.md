Sample project with basic 2-factor authentication using Spring
Security. The source code is in
[github](https://github.com/dsyer/two-factor).

The first factor is a standard login form (username and password), but
any Spring Security login will work the same way. The second factor in
this sample is a toy one (the user's favourite colour), but it is easy
to change that bit into something more realistic. The key parts of the
implementation are as follows.

## Use a Special Role

The application resources are protected with an additional role that
would not be present in a normal authentication:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
       ...
       .authorizeRequests().antMatchers("/factor/**").authenticated()
            .anyRequest().hasRole("FACTOR");
}
```

So there is a special role that protects all resources except
"/factor/**", which is where we are going to handle the second factor.

## Custom Access Denied Handler

An `AccessDeniedHandler` is used that checks for the special role, and
redirects to a prompt for the additional information:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.requestCache().requestCache(requestCache)
        .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler())
        ...;
}
```

## Handler for the Extra Factor

A `@Controller` is provided that prompts the user for the extra factor
and handles the response. The implementation here is super simple: it
just presents the user with a form to type in their favourite
colour:

```java
@GetMapping("/factor")
public String factor() {
    return "factor";
}
```

If the favourite colour is "red" then they are authenticated, and the
response is handled by a
`SavedRequestAwareAuthenticationSuccessHandler` (just like a normal
login success):

```java
@PostMapping("/factor")
public void accept(@RequestParam String factor, Principal principal,
        HttpServletRequest request, HttpServletResponse response) throws Exception {
    if (!"red".equals(factor)) {
        response.sendRedirect("/factor?error=true");
        return;
    }
    Authentication successful = addFactorRole(principal);
    SecurityContextHolder.getContext().setAuthentication(successful);
    handler.onAuthenticationSuccess(request, response, successful);
}
```

For a real implementation you could do a token-based authentication
(for instance) instead.

## Saving the Request

We want to remember the user's original request across the whole
authentication, and the default strategy provided by Spring Security
discards the saved request after the first stage. So to extend its
memory, we add a request cache and set it up so that only an
authentication with the special role causes the saved request to be
discarded:

```java
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
```
