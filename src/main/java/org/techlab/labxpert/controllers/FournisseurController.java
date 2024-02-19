package org.techlab.labxpert.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.techlab.labxpert.dtos.FournisseurDTO;
import org.techlab.labxpert.service.I_Fournisseur;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;

@RestController
@CrossOrigin("*")
@RequestMapping(value="/api/v1/fournisseur", produces = "application/json")
public class FournisseurController {

    @Autowired
    I_Fournisseur i_fournisseur;

    @GetMapping
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<List<FournisseurDTO>> showFournisseurs(){
        // API pour Afficher Liste Fournisseur
        List<FournisseurDTO> fournisseurDTOS=i_fournisseur.showFournisseurs();
        return new ResponseEntity<>(fournisseurDTOS, HttpStatus.OK);
    }
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<FournisseurDTO> getFournisseur(@PathVariable(value = "id") Long id_fournisseur){
        // API pour Afficher fournisseur par  id
        FournisseurDTO fournisseurDTO=i_fournisseur.getFournisseur(id_fournisseur);
        return new ResponseEntity<>(fournisseurDTO, HttpStatus.OK);
    }
    @PostMapping
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<FournisseurDTO> addFournisseur(@RequestBody @Valid FournisseurDTO fournisseurDTO){
        // API pour Ajouter Fournisseur
        FournisseurDTO fournisseur=i_fournisseur.addFournisseur(fournisseurDTO);
        return new ResponseEntity<>(fournisseur, HttpStatus.CREATED);
    }
    @PutMapping
    @PreAuthorize("hasAuthority('Responsable')")
    public ResponseEntity<FournisseurDTO> modFournisseur(@RequestBody @Valid FournisseurDTO fournisseurDTO){
        // API pour modifier Fournisseur
        FournisseurDTO fournisseur=i_fournisseur.modFournisseur(fournisseurDTO);
        return new ResponseEntity<>(fournisseur, HttpStatus.OK);
    }
    @DeleteMapping("{id}")
    @PreAuthorize("hasAuthority('Responsable')")
    public HashMap<String,Boolean> delFournisseur(@PathVariable(value = "id") Long id_fournisseur){
        // API pour Supprimer Fournisseur
        FournisseurDTO fournisseurDTO=i_fournisseur.getFournisseur(id_fournisseur);
        HashMap<String,Boolean> response=new HashMap<>();
        if(i_fournisseur.delFournisseur(fournisseurDTO)){
            response.put("delete",Boolean.TRUE);
        }
        return response;
    }
}
