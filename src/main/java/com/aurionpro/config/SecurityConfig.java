package com.aurionpro.config;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.aurionpro.security.JwtAuthenticationFilter;
import com.aurionpro.security.JwtAuthenticationentryPoint;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private JwtAuthenticationentryPoint authenticationEntryPoint;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // ⚡ CORS Configuration for Spring Security
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
                "http://localhost:4200",           // Angular dev
               "https://flourishing-bonbon-d77f71.netlify.app" // Production Angular app
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("Authorization")); // JWT token header
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .cors(withDefaults()) // ⚡ Uses the above CorsConfigurationSource
            .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
            .authorizeHttpRequests(request -> request
            		.requestMatchers("/actuator/**").permitAll()
                // Public Endpoints
                .requestMatchers("/user/Register").permitAll()
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/urlapp/auth/**").permitAll()
                .requestMatchers("/urlapp/transaction/**").permitAll()
                .requestMatchers("/urlapp/query/**").permitAll()
                .requestMatchers("/urlapp/buyplan/**").permitAll()
                .requestMatchers(HttpMethod.PUT, "/urlapp/query/adminResponse").permitAll()
                .requestMatchers(HttpMethod.GET, "/urlapp/plan/view").permitAll()
                .requestMatchers(HttpMethod.POST, "/urlapp/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/urlapp/user/register").permitAll()

                // Admin Endpoints
                .requestMatchers("/urlapp/admin/**").hasAuthority("ROLE_ADMIN")
                .requestMatchers("/urlapp/plan/**").hasAuthority("ROLE_ADMIN")

                // Customer/User Endpoints
                .requestMatchers("/urlapp/user/**").hasAnyAuthority("ROLE_CUSTOMER", "ROLE_ADMIN")
                .requestMatchers("/urlapp/generateurl/**").hasAnyAuthority("ROLE_CUSTOMER")

                // All Other Requests
                .anyRequest().authenticated()
            )
            .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); //4th part

        return http.build();
    }
}










//package com.aurionpro.config;
//
//import static org.springframework.security.config.Customizer.withDefaults;
//import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import com.aurionpro.security.JwtAuthenticationFilter;
//import com.aurionpro.security.JwtAuthenticationentryPoint;
//
//@Configuration
//@EnableMethodSecurity
//public class SecurityConfig {
//
//    @Autowired
//    private JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Autowired
//    private JwtAuthenticationentryPoint authenticationEntryPoint;
//
//    @Bean
//    public static PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//        return configuration.getAuthenticationManager();
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//
//        http.csrf(csrf -> csrf.disable())
//            .cors(withDefaults())
//            .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
//            .authorizeHttpRequests(request -> request
//                // Public Endpoints
//                .requestMatchers("/user/Register").permitAll()
//                .requestMatchers("/auth/**").permitAll()
//                .requestMatchers("/urlapp/auth/**").permitAll()
//                .requestMatchers("/urlapp/transaction/**").permitAll()
//                .requestMatchers("/urlapp/query/**").permitAll()
//                .requestMatchers("/urlapp/buyplan/**").permitAll()
//                .requestMatchers("/urlapp/generateurl/**").permitAll()
//                .requestMatchers(HttpMethod.PUT, "/urlapp/query/adminResponse").permitAll()
//                .requestMatchers(HttpMethod.GET, "/urlapp/plan/view").permitAll()
//                .requestMatchers(HttpMethod.POST, "/urlapp/auth/login").permitAll()
//                .requestMatchers(HttpMethod.POST, "/urlapp/user/register").permitAll()
//
//                // Admin Endpoints
//                .requestMatchers("/urlapp/admin/**").hasAuthority("ROLE_ADMIN")
//                .requestMatchers("/urlapp/plan/**").hasAuthority("ROLE_ADMIN")
//
//                // Customer/User Endpoints
//                .requestMatchers("/urlapp/user/**").hasAnyAuthority("ROLE_CUSTOMER", "ROLE_ADMIN")
//
//                // All Other Requests
//                .anyRequest().authenticated()
//            )
//            .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))
//            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//
//        return http.build();
//    }
//}
