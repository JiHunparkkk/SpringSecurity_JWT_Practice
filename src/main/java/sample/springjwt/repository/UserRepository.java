package sample.springjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sample.springjwt.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUsername(String username);
}
