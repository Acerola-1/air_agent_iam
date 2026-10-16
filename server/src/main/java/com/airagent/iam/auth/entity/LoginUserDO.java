package com.airagent.iam.auth.entity;

import java.util.UUID;

/** 数据库结果对象。 */
public record LoginUserDO(UUID id, String passwordHash, String status) {
    @Override
    public String toString() {
        return "LoginUserDO[id=" + id + ", status=" + status + "]";
    }
}
