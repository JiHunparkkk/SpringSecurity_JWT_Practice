package sample.springjwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import sample.springjwt.dto.JoinDto;
import sample.springjwt.service.JoinService;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(@RequestBody JoinDto joinDto) {
        joinService.join(joinDto);
        return "ok";
    }
}
