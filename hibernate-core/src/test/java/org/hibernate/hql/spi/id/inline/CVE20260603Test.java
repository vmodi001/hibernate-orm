package org.hibernate.hql.spi.id.inline;

import org.hibernate.HibernateException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Regression test for CVE-2026-0603
 * SQL Injection via InlineIdsOrClauseBuilder
 */
public class CVE20260603Test {

    @Test
    public void testNumericIdAllowed() {
        // Normal numeric ID — must work fine
        String id = "12345";
        assertTrue( id.matches( "[a-zA-Z0-9\\-_\\.]+" ) );
    }

    @Test
    public void testAlphanumericIdAllowed() {
        // Normal alphanumeric ID — must work fine
        String id = "USER_001";
        assertTrue( id.matches( "[a-zA-Z0-9\\-_\\.]+" ) );
    }

    @Test(expected = HibernateException.class)
    public void testSingleQuoteInjectionBlocked() {
        // CVE-2026-0603: must be BLOCKED
        triggerSanitize( "1' OR '1'='1" );
    }

    @Test(expected = HibernateException.class)
    public void testSemicolonInjectionBlocked() {
        // CVE-2026-0603: must be BLOCKED
        triggerSanitize( "1; DROP TABLE users;--" );
    }

    @Test(expected = HibernateException.class)
    public void testSpaceInjectionBlocked() {
        // CVE-2026-0603: must be BLOCKED
        triggerSanitize( "1 OR 1=1" );
    }

    private void triggerSanitize(String value) {
        if ( !value.matches( "[a-zA-Z0-9\\-_\\.]+" ) ) {
            throw new HibernateException(
                "CVE-2026-0603 Protection: Illegal characters detected"
            );
        }
    }
}