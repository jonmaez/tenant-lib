package com.ahsanb.tenantlib.security;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequestAuthorization {
}
