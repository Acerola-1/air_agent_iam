package com.airagent.iam.ops;

/** 运维命令的显式冲突：目标不存在、主体停用、角色冲突或参数不满足写前条件。 */
public class OpsConflictException extends RuntimeException {

    public OpsConflictException(String message) {
        super(message);
    }
}
