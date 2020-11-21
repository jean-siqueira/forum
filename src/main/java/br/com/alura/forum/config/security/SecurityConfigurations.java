package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfigurations extends WebSecurityConfigurerAdapter {

    @Autowired
    private AutenticacaoService autenticacaoService;

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    //configurações de autenticação
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(autenticacaoService).passwordEncoder(new BCryptPasswordEncoder());
    }

    //configurações de autorização
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
       http.authorizeRequests()
           .antMatchers(HttpMethod.GET, "/topicos").permitAll()
           .antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
           .antMatchers(HttpMethod.POST, "/auth").permitAll()
           .anyRequest().authenticated()
           .and().csrf().disable() //desabilita a avalidação de ataque crossdomain
           .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//cria uma sessão sem estado
           .and().addFilterBefore(new AutenticacaoViaTokenFilter(), UsernamePasswordAuthenticationFilter.class); //define a ordem de utilização dos filtros

    }

    //Configurações de recursos estáticos(js, css, imagens, etc)
    @Override
    public void configure(final WebSecurity web) throws Exception {
    }

}
