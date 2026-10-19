package com.airagent.iam.ops.entity;

import java.util.UUID;

/** 企业成员关系视图。 */
public record OpsMembershipDO(UUID id, String status, long revision) {
}
