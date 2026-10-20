package com.airagent.iam.internal.service;

import com.airagent.iam.config.IamProperties;
import com.airagent.iam.internal.dto.ExecutionContextRefDTO;
import com.airagent.iam.internal.dto.KnowledgeDelegationDTO;
import com.airagent.iam.internal.dto.RevisionsDTO;
import com.airagent.iam.internal.entity.IssuedKnowledgeDelegationDO;
import com.airagent.iam.internal.mapper.IdentityMapper;
import com.airagent.iam.internal.service.impl.KnowledgeDelegationServiceImpl;
import com.airagent.iam.internal.vo.RecheckActiveVO;
import com.airagent.iam.security.internal.InternalClient;
import com.airagent.iam.web.error.ApiException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** G0：签发必须通过既有 PG+Redis 源会话复查，而非只看 PG 行。 */
class KnowledgeDelegationServiceTest {
    private final IdentityMapper db = mock(IdentityMapper.class);
    private final IntrospectionService introspection = mock(IntrospectionService.class);
    private final IamProperties props = mock(IamProperties.class);
    private final UUID tenant = UUID.fromString("01940000-0000-4000-8000-000000000002");
    private final RevisionsDTO revisions = new RevisionsDTO(1L, 1L, 1L, 1L);
    private final InternalClient client = new InternalClient("agent-test", "test",
            List.of("knowledge-delegation:issue"), List.of("knowledge", "langgraph-runtime"), "active");

    private KnowledgeDelegationServiceImpl service() {
        when(props.internal()).thenReturn(new IamProperties.Internal(60, 43200, null, 60, List.of("knowledge-test")));
        return new KnowledgeDelegationServiceImpl(db, props, JsonMapper.builder().build(), introspection);
    }
    private KnowledgeDelegationDTO request(String operation) {
        return new KnowledgeDelegationDTO("iam.knowledge-delegation-request.v1",
                new ExecutionContextRefDTO(UUID.randomUUID().toString(), revisions), tenant.toString(), operation);
    }
    @Test void revokedOrRedisMissingDoesNotPersistDelegation() {
        var service = service();
        when(introspection.introspect(any(), any())).thenReturn(null);
        assertThrows(ApiException.class, () -> service.issue(client, request("query")));
        verifyNoInteractions(db);
    }
    @Test void sourceBackendFailureDoesNotPersistDelegation() {
        var service = service();
        when(introspection.introspect(any(), any())).thenThrow(new IllegalStateException("backend unavailable"));
        assertThrows(IllegalStateException.class, () -> service.issue(client, request("query")));
        verifyNoInteractions(db);
    }
    @Test void missingOperationIsBadRequestBeforeAnyBackendCall() {
        var service = service();
        assertThrows(ApiException.class, () -> service.issue(client, request(null)));
        verifyNoInteractions(db, introspection);
    }
    @Test void liveReferencePositiveControlIssuesBoundSingleOperation() {
        var service = service();
        when(introspection.introspect(any(), any())).thenReturn(new RecheckActiveVO(true, true, revisions, "2026-10-20T00:00:00Z"));
        when(db.createKnowledgeDelegation(anyString(), any(), anyString(), anyString(), anyLong()))
                .thenReturn(new IssuedKnowledgeDelegationDO(OffsetDateTime.now().plusSeconds(30),
                    UUID.randomUUID(), UUID.randomUUID(), tenant, UUID.randomUUID(), 1L,
                    "{\"user_auth_revision\":1,\"tenant_auth_revision\":1,\"membership_revision\":1,\"session_ctx_version\":1}"));
        var result = service.issue(client, request("query"));
        assertEquals("query", result.operation());
        assertEquals("knowledge", result.audience());
        assertTrue(result.delegationToken().startsWith("kdl_"));
        verify(introspection).introspect(eq(client), argThat(dto -> dto.audience().equals("langgraph-runtime") && dto.executionContext() != null));
    }
}
