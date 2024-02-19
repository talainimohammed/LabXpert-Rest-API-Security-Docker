package org.techlab.labxpert.repository;

import org.springframework.data.jpa.repository.Query;
import org.techlab.labxpert.entity.Utilisateur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UtilisateurRepository extends JpaRepository<Utilisateur,Long> {
    List<Utilisateur> findByDeletedFalse();
    Utilisateur findUtilisateurByNomUtilisateur(String username);
}
