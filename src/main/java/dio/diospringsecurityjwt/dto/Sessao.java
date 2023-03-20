package dio.diospringsecurityjwt.dto;

public class Sessao {
    //ao socilitar o login, vamos soliciar a sessao
    //aqui pode ter N caracteristicas que acharmos conveniente retornar para o usuario(cliente)
    //aqui vamos retornar login e token

    private String login;
    private String token;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
