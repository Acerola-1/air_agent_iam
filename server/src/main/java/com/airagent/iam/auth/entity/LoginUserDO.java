package com.airagent.iam.auth.entity;

import java.util.UUID;

/**
 * 登录核验所需的账号最小行（DO，仅 {@link com.airagent.iam.auth.mapper.SessionMapper#findLogin} 使用，不对外）。
 *
 * <p>来源为 SECURITY DEFINER 函数 {@code iam_auth.find_user_for_login(realm, account)}
 * （SQL 见 mapper/auth/SessionMapper.xml）。请求角色 iam_app 对
 * {@code iam.users.password_hash} 无直接读权限（V15），口令摘要是该引导函数放开的唯一例外，
 * 因此摘要是服务端内存中的临时数据：既不出现在任何响应，也不写日志。
 *
 * <p>同 realm 下账号不存在时 Mapper 返回 {@code null}；存在但状态非 {@code active} 的行仍会返回，
 * 由调用方与口令校验一起折叠为同一个 401，避免账号枚举。
 *
 * @param id           用户主键（iam.users.id）
 * @param passwordHash BCrypt 摘要（$2b$ / cost 10），只用于内存比对；{@code toString()} 已剔除该字段
 * @param status       账号状态，仅 {@code active} / {@code disabled}
 * @author Acerola
 */
public record LoginUserDO(UUID id, String passwordHash, String status) {

    /**
     * 脱敏输出：保留定位信息，绝不带出口令摘要。
     *
     * @return 仅含 id 与 status 的文本
     */
    @Override
    public String toString() {
        return "LoginUserDO[id=" + id + ", status=" + status + "]";
    }
}
