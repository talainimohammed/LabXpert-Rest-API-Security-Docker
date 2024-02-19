package org.techlab.labxpert.config;

public class JWTUtil {
    public static final long EXPIRE_ACCESS_TOKEN = 1*60*1000;
    public static final String ISSUER = "SpringBootApp";
    public static final  String SECRET_KEY = "Talaini1546548233";
    public static final String BEARER_PRIFIX="Bearer ";
    public static final  long EXPIRE_REFRESH_TOKEN = 120*60*1000;
    public static final String AUTH_HEADER = "Authorization";
}
