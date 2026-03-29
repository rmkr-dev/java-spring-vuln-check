package hawk;

import hawk.api.jwt.JwtFilter;
import hawk.api.jwt.JwtTokenProvider;
import hawk.api.token.TokenFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class MultiHttpSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        UserDetails user2 = User.builder()
                .username("janesmith")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, user2);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http, JwtTokenProvider jwtTokenProvider) throws Exception {
        http.securityMatcher("/api/jwt/**")
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/jwt/auth/signin").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new JwtFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain tokenFilterChain(
            HttpSecurity http,
            @Value("${token.http.auth.name:SH_AUTH_TOKEN}") String authHeaderName,
            @Value("${token.http.auth.value:ITSASECRET}") String authHeaderValue) throws Exception {

        TokenFilter filter = new TokenFilter(authHeaderName);
        filter.setAuthenticationManager(auth -> {
            String principal = (String) auth.getPrincipal();
            if (!authHeaderValue.equals(principal)) {
                throw new BadCredentialsException("The API key was not found or not the expected value.");
            }
            auth.setAuthenticated(true);
            return auth;
        });

        http.securityMatcher("/api/token/**")
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(filter)
                .addFilterBefore(new ExceptionTranslationFilter(new Http403ForbiddenEntryPoint()), TokenFilter.class)
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain basicFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/basic/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain formFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
                        .requestMatchers(
                                "/",
                                "/jwt-auth",
                                "/token-auth",
                                "/basic-auth",
                                "/openapi/**",
                                "/openapi.yaml",
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/log4j",
                                "/hidden",
                                "/hidden/*",
                                "/login-code",
                                "/login-form-multi"
                        ).permitAll()
                        .anyRequest().authenticated())
                .formLogin(f -> f.loginPage("/login").permitAll())
                .logout(l -> l.logoutSuccessUrl("/").permitAll());
        return http.build();
    }
}
