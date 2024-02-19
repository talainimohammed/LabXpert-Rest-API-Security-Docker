package org.techlab.labxpert.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.techlab.labxpert.dtos.OutilDTO;
import org.techlab.labxpert.service.I_Outil;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;

@RestController
@CrossOrigin("*")
@RequestMapping(value="/api/v1/outil", produces = "application/json")
public class OutilController {
    @Autowired
    I_Outil i_outil;

    @GetMapping
    @PreAuthorize("hasAuthority('Preleveur')")
    public ResponseEntity<List<OutilDTO>> allOutils(){
        // API Afficher tous les outils
        List<OutilDTO> outilDTOS=i_outil.allOutils();
        return new ResponseEntity<>(outilDTOS, HttpStatus.OK);
    }
    @PostMapping
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<OutilDTO> addOutil(@RequestBody @Valid OutilDTO outilDTO){
        // API pour Ajouter Outil
        OutilDTO outiladded=i_outil.addOutil(outilDTO);
        return new ResponseEntity<>(outiladded, HttpStatus.CREATED);
    }
    @PutMapping
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<OutilDTO> modOutil(@RequestBody @Valid OutilDTO outilDTO){
        // API pour modifier Outil
        OutilDTO outilupdated=i_outil.modOutil(outilDTO);
        return new ResponseEntity<>(outilupdated, HttpStatus.OK);
    }
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('Responsable')")
    public HashMap<String,Boolean> delOutil(@PathVariable(value = "id") Long id_outil){
        // API pour Supprimer Outil
        OutilDTO outilDTO=i_outil.outilById(id_outil);
        HashMap<String,Boolean> response=new HashMap<>();
        if(i_outil.delOutil(outilDTO)){
            response.put("delete",Boolean.TRUE);
        }
        return response;
    }
}
