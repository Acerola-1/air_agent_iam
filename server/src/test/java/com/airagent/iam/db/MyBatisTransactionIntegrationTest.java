package com.airagent.iam.db;

import com.airagent.iam.common.mapper.RequestContextMapper;
import java.util.UUID;
import org.apache.ibatis.session.LocalCacheScope;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 验证 MyBatis 与 Spring 共用真实事务及受限连接，防止迁移后租户上下文脱离业务事务。
 */
@SpringBootTest
@ActiveProfiles("it")
class MyBatisTransactionIntegrationTest {

    @Autowired
    private RequestContextMapper requestContextMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private SqlSessionFactory sqlSessionFactory;

    @Test
    void contextChangesShareTheSpringConnectionAndRollbackWithoutLeaking() {
        UUID userId = UUID.randomUUID();
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        Integer backendPid = transactionTemplate.execute(status -> {
            Integer pid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
            assertEquals(1, requestContextMapper.setContext(userId, tenantA, false));
            assertEquals(tenantA.toString(), readTenantContext());
            assertEquals(1, requestContextMapper.setContext(userId, tenantB, false));
            assertEquals(tenantB.toString(), readTenantContext());
            assertEquals(pid, jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class));
            status.setRollbackOnly();
            return pid;
        });

        // it 配置限定一个物理连接；回滚后从同一后端核对无租户遗留。
        assertEquals(backendPid, jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class));
        String tenantContext = readTenantContext();
        assertTrue(tenantContext == null || tenantContext.isEmpty());
        assertEquals("iam_app", jdbcTemplate.queryForObject("SELECT current_user", String.class));
    }

    @Test
    void authorizationQueriesDoNotEnableCrossStatementOrSecondLevelCaching() {
        org.apache.ibatis.session.Configuration configuration = sqlSessionFactory.getConfiguration();
        assertFalse(configuration.isCacheEnabled());
        assertEquals(LocalCacheScope.STATEMENT, configuration.getLocalCacheScope());
    }

    private String readTenantContext() {
        return jdbcTemplate.queryForObject("SELECT current_setting('app.tenant_id', true)", String.class);
    }
}
