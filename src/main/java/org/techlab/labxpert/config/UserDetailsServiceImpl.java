package org.techlab.labxpert.config;

import org.techlab.labxpert.dtos.UtilisateurDTO;
import org.techlab.labxpert.entity.Utilisateur;
import org.techlab.labxpert.service.I_Utilisateur;
import org.techlab.labxpert.service.serviceImp.UtilisateurServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


import java.util.Collections;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private I_Utilisateur utilisateurService;

    public UserDetailsServiceImpl(I_Utilisateur utilisateurService) {
        this.utilisateurService = utilisateurService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UtilisateurDTO utilisateur = utilisateurService.authentification(username);
        if (utilisateur == null) throw new UsernameNotFoundException("USER NOT FOUND");
        GrantedAuthority authority = new SimpleGrantedAuthority(utilisateur.getRole().name());
        return new User(utilisateur.getNomUtilisateur(),utilisateur.getPassword(), Collections.singleton(authority));

    }

}
