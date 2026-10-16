package com.airagent.iam.internal.service;

import com.airagent.iam.auth.AuthoritySnapshot;
import com.airagent.iam.internal.dto.IntrospectDTO;
import com.airagent.iam.security.internal.InternalClient;

/** 内部双主体身份核验。 */
public interface IntrospectionService {
    String INTROSPECTION_SCHEMA = "iam.introspection.v1";
    String RUNTIME_AUDIENCE = "langgraph-runtime";
    Object introspect(InternalClient client, IntrospectDTO request);
    AuthoritySnapshot loadHumanSnapshot(String digest);
}
