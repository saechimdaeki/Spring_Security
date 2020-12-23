package security.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "호옹이!";
    }

    @GetMapping("loginPage")
    public String loginPage(){
        return "loginPage";
    }
}
