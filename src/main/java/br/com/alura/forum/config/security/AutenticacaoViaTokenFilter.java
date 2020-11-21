package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.security.TokenService;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {

    private TokenService tokenService;

    public AutenticacaoViaTokenFilter(final TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest httpServletRequest,
        final HttpServletResponse httpServletResponse,
        final FilterChain filterChain) throws ServletException, IOException {

        String token = recuperarToken(httpServletRequest);

        boolean valido = tokenService.isTokenValido(token);

        System.out.println(valido);

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
