package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(final HttpServletRequest httpServletRequest,
        final HttpServletResponse httpServletResponse,
        final FilterChain filterChain) throws ServletException, IOException {

        String token = recuperarToken(httpServletRequest);
        System.out.println(token);
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private String recuperarToken(final HttpServletRequest httpServletRequest) {
        final String token = httpServletRequest.getHeader("Authorization");
        if(token == null || token.isEmpty() || !token.startsWith("Bearer")) {
            return null;
        }
        return token.substring(7, token.length());
    }
}
