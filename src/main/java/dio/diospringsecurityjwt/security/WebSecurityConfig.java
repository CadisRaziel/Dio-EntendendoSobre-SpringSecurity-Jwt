package dio.diospringsecurityjwt.security;


import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.h2.server.web.WebServlet;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //-> habilita a pre verificação nas rotas globalmente
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public BCryptPasswordEncoder encoder(){
        //tipo de criptografia para por na senha do usuario
        return new BCryptPasswordEncoder();
    }

    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();

        //aqui no cors estou dizendo que ela vai ser interceptada por um filtro(JWTFilter)
        http.cors().and().csrf().disable()
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()

                //requisições liberadas SEM token(authenticação)
                .antMatchers(SWAGGER_WHITELIST).permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers(HttpMethod.POST,"/login").permitAll()
                .antMatchers(HttpMethod.POST,"/users").permitAll()

                //requisições liberadas COM TOKEN(authenticação)
                .antMatchers(HttpMethod.GET,"/users").hasAnyRole("USERS","MANAGERS")
                .antMatchers("/managers").hasAnyRole("MANAGERS")
                .anyRequest().authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
    @Bean
    public ServletRegistrationBean h2servletRegistration(){
        //HABILITANDO ACESSAR O H2-DATABSE NA WEB PARA VISUALIZAR EM UM CONSOLE
        //como a aplicação esta segura precisamos fazer de um jeito para poder acessar sem precisar de credencial
        //para conseguimos importar o 'WebServelet' é preciso ir la na dependencia do h2 e remover o '<scope>runtime</scope>'

        //http://localhost:8080/h2-console -> URL para acessar o banco de dados WEB
        //caso der erro, verifique o JDBC URL, se tive diferente do application.properties coloque essa igual ta la 'jdbc:h2:mem:testdb'
        ServletRegistrationBean registrationBean = new ServletRegistrationBean( new WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }
}