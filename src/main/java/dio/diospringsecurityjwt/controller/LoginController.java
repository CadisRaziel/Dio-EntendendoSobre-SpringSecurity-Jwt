package dio.diospringsecurityjwt.controller;

import dio.diospringsecurityjwt.dto.Login;
import dio.diospringsecurityjwt.dto.Sessao;
import dio.diospringsecurityjwt.model.User;
import dio.diospringsecurityjwt.repository.UserRepository;
import dio.diospringsecurityjwt.security.JWTCreator;
import dio.diospringsecurityjwt.security.JWTObject;
import dio.diospringsecurityjwt.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
public class LoginController {
    //classe responsavel por gerar o token atraves de uma requisição de login na api
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private SecurityConfig securityConfig;
    @Autowired
    private UserRepository repository;

    @PostMapping("/login")
    //vamos receber um login via requestbody
    //ele vai nos retornar um objeto sessao
    public Sessao logar(@RequestBody Login login) {

        //locanizando atraves do username passado pelo login
        User user = repository.findByUsername(login.getUsername());
        if (user != null) {
            //vamos pegar a senha enviada 'passwordOk' e o 'encoder.matches' vai verifica no banco se ta certa a senha
            boolean passwordOk = encoder.matches(login.getPassword(), user.getPassword());
            if (!passwordOk) {
                throw new RuntimeException("Senha inválida para o login: " + login.getUsername());
            }
            //se a senha estiver ok
            //Estamos enviando um objeto Sessão para retornar mais informações do usuário
            Sessao sessao = new Sessao();
            sessao.setLogin(user.getUsername());

            JWTObject jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration((new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION)));
            jwtObject.setRoles(user.getRoles());

            //gerando o token com o nosso objeto localizado na aplicação
            sessao.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY, jwtObject));
            return sessao;
        } else {
            throw new RuntimeException("Erro ao tentar fazer login");
        }
    }
}