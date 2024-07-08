package sample.springjwt.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import sample.springjwt.dto.JoinDto;
import sample.springjwt.entity.UserEntity;
import sample.springjwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(JoinDto joinDto) {
        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {

            return;
        }

        UserEntity data = new UserEntity();
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));   //TODO: BCrypt는 보안상 문제가 있다고한다. 왜 그런지 이유와 대안책을 알아보자.
        data.setRole("ROLE_ADMIN"); //스프링은 앞단에 ROLE 을 붙인다

        userRepository.save(data);
    }
}
