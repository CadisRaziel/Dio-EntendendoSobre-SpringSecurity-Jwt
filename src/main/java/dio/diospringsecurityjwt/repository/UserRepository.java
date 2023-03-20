package dio.diospringsecurityjwt.repository;

import dio.diospringsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


public interface UserRepository extends JpaRepository<User, Integer> {
    //esses dois metodos vao no banco de dados e me trazer suas informações
    //@Query -> Vou precisar trazer um usuario pelo seu 'username'
    //@Query -> JPQL que retorna um usuario
    @Query("SELECT e FROM User e JOIN FETCH e.roles WHERE e.username= (:username)")
    public User findByUsername(@Param("username") String username);

    //se existe um usuario
    boolean existsByUsername(String username);
}

