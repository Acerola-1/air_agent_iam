package com.airagent.iam.internal.service;

import com.airagent.iam.internal.dto.RuntimeTicketDTO;
import com.airagent.iam.internal.vo.RuntimeTicketVO;
import com.airagent.iam.security.internal.InternalClient;

/** 运行时短票据业务。 */
public interface RuntimeTicketService {
    RuntimeTicketVO issue(InternalClient client, RuntimeTicketDTO request);
}
