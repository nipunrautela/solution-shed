package com.nipunrautela.solutionshed.security.jwt;

import com.nipunrautela.solutionshed.user.User;
import com.nipunrautela.solutionshed.user.UserService;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final HandlerExceptionResolver resolver;
    private final UserService userService;

    @Autowired
    public JwtFilter(
            JwtService jwtService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver,
            UserService userService
    ) {
        this.jwtService = jwtService;
        this.resolver = resolver;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = "";

        try {
            if (authHeader != null && authHeader.startsWith("Bearer")) {
                token = authHeader.substring(7);
            }

            JwtData jwtData = jwtService.getJwtData(token);

            if (jwtData.getSubject() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
                User user = userService.loadUserByUsername(jwtData.getSubject());

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        user, null, user.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        catch (Exception e) {
            this.resolver.resolveException(request, response, null, e);
        }

        filterChain.doFilter(request, response);
    }
}
