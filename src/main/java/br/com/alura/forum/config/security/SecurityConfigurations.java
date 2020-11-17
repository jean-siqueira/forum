package br.com.alura.forum.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter {

    //configurações de autenticação
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
    }

    //configurações de Autorização
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
       http.authorizeRequests()
           .antMatchers(HttpMethod.GET, "/topicos").permitAll()
           .antMatchers(HttpMethod.GET, "/topicos/*").permitAll();
    }

    //Configurações de recursos estáticos(js, css, imagens, etc)
    @Override
    public void configure(final WebSecurity web) throws Exception {
    }
}
