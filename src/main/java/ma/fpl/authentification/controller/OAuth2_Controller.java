package ma.fpl.authentification.controller;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2_Controller {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    public OAuth2_Controller(AuthenticationManager authenticationManager,
                             UserDetailsService userDetailsService,
                             JwtEncoder jwtEncoder,
                             JwtDecoder jwtDecoder) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    // a. Authentification et génération des tokens
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestParam String username,
                                                     @RequestParam String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            String scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));

            return ResponseEntity.ok(Map.of(
                    "access_token", generateToken(username, scope, 5),
                    "refresh_token", generateToken(username, null, 60)));
        } catch (AuthenticationException e) {
            System.out.println("username ou mot de passe errone ");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Identifiants incorrects"));
        }
    }

    // b. Renouvellement de l'Access Token à partir du Refresh Token
    @PostMapping("/refreshToken")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestParam String refreshToken) {
        try {
            Jwt decoded = jwtDecoder.decode(refreshToken);
            UserDetails user = userDetailsService.loadUserByUsername(decoded.getSubject());
            System.out.println(user.getUsername());
            System.out.println(user.getPassword());
            String scope = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));

            return ResponseEntity.ok(Map.of(
                    "access_token", generateToken(user.getUsername(), scope, 5),
                    "refresh_token", refreshToken));
        } catch (JwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token invalide ou expiré"));
        }
    }

    // Méthode utilitaire de génération d'un JWT signé avec la clé privée RSA
    private String generateToken(String username, String scope, long minutes) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject(username)
                .issuedAt(now)
                .expiresAt(now.plus(minutes, ChronoUnit.MINUTES))
                .issuer("auth-service");
        if (scope != null) {
            claims.claim("scope", scope);
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(claims.build())).getTokenValue();
    }
}