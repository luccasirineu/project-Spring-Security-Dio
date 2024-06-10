package com.br.spring_security_dio.repository;

import com.br.spring_security_dio.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Integer> {
    @Query("SELECT e FROM User e JOIN FETCH e.roles WHERE e.username= (:username)")
    User findByUsername(@Param("username") String username);

    boolean existsByUsername(String username);
}