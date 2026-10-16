package com.airagent.iam.auth.entity;

/** 数据库结果对象。 */
public record OutboxEventDO(long id, String kind, String payloadJson, int attempts) {
}
