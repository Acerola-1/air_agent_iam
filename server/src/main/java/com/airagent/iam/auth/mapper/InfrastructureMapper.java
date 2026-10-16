package com.airagent.iam.auth.mapper;

import com.airagent.iam.auth.entity.BootstrapUserDO;
import com.airagent.iam.auth.entity.OutboxEventDO;
import com.airagent.iam.auth.entity.ProvisionResultDO;
import java.util.List;
import java.util.UUID;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/** InfrastructureMapper 的类型化数据访问，SQL 由同名 XML 定义。 */
@Mapper
public interface InfrastructureMapper {

    BootstrapUserDO ensureUser(
            @Param("account") String account,
            @Param("displayName") String displayName,
            @Param("passwordHash") String passwordHash,
            @Param("roleId") UUID roleId);

    ProvisionResultDO ensureRuntimeClient(
            @Param("clientId") String clientId,
            @Param("secretDigest") String secretDigest);

    boolean ensureSsoClient(
            @Param("clientId") String clientId,
            @Param("name") String name,
            @Param("secretDigest") String secretDigest,
            @Param("callbackUrl") String callbackUrl,
            @Param("origins") List<String> origins,
            @Param("audience") String audience);

    List<OutboxEventDO> claimOutbox(@Param("batchSize") int batchSize);

    int completeOutbox(@Param("id") long id);

    int requeueOutbox(@Param("id") long id, @Param("maxAttempts") int maxAttempts);
}
