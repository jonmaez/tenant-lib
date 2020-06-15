package com.ahsanb.tenantlib.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ahsanb.tenantlib.master.entities.MasterTenant;
import com.ahsanb.tenantlib.master.services.MasterTenantService;
import com.ahsanb.tenantlib.util.JWTConstants;
import com.ahsanb.tenantlib.util.JwtTokenUtil;
import com.ahsanb.tenantlib.util.TenantContextHolder;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

/**
 * @author Md. Amran Hossain
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    
    @Autowired
    MasterTenantService masterTenantService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(JWTConstants.HEADER_STRING);
        String audience = null; //tenantId
        String authToken = null;
        if (header != null && header.startsWith(JWTConstants.TOKEN_PREFIX)) {
            authToken = header.replace(JWTConstants.TOKEN_PREFIX,"");
            try {
                audience = jwtTokenUtil.getAudienceFromToken(authToken);
                MasterTenant masterTenant = masterTenantService.findByTenantId(audience);
                if(null == masterTenant){
                    logger.error("An error during getting tenant name");
                    throw new BadCredentialsException("Invalid tenant and user.");
                }
                TenantContextHolder.setTenantId(masterTenant.getTenantId());
            } catch (IllegalArgumentException ex) {
                logger.error("An error during getting username from token", ex);
            } catch (ExpiredJwtException ex) {
                logger.warn("The token is expired and not valid anymore", ex);
            } catch(SignatureException ex){
                logger.error("Authentication Failed. Username or Password not valid.",ex);
            }
        } else {
            logger.warn("Couldn't find bearer string, will ignore the header");
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
