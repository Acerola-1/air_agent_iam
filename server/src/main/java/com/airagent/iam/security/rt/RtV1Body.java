package com.airagent.iam.security.rt;

import java.util.UUID;

/**
 * rt-v1 运行票据正文。
 *
 * <p>字段顺序固定，参与紧凑 JSON 序列化：sid,uid,tid,mid,aud,iat,exp,crev,urev,trev,mrev。
 */
public record RtV1Body(
        UUID sid,
        UUID uid,
        UUID tid,
        UUID mid,
        String aud,
        long iat,
        long exp,
        long crev,
        long urev,
        long trev,
        long mrev) {
}
