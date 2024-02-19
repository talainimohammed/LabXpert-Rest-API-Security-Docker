package org.techlab.labxpert.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@CrossOrigin("*")
@RequestMapping(value ="/testafterlogin", produces = "application/json")
public class AfterloginController {

    @GetMapping
    public String show(){
        return "testafterlogin";
    }
}
