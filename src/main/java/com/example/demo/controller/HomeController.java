package com.example.demo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class HomeController {

    @RequestMapping("/secured-saml")
    public String securedSaml(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

    @RequestMapping("/nonSecured")
    public String nonSecured() {
        return "nonSecured";
    }

    @RequestMapping("/secured-oauth")
    public String securedOauth(Principal principal, Model model) {
        try {
            model.addAttribute("name", principal.getName());

            String email = principal instanceof Saml2AuthenticatedPrincipal ?
                    ((Saml2AuthenticatedPrincipal) principal).getFirstAttribute("email") :
                    null;
            model.addAttribute("emailAddress", email);
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }

        return "secured";
    }
}
