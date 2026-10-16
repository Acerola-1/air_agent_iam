package com.airagent.iam.health.mapper;

import org.apache.ibatis.annotations.Mapper;

/**
 * PostgreSQL 连接探测（Mapper 层，SQL 见 mapper/health/HealthMapper.xml）。
 *
 * <p>语句只有一条不触表的 {@code SELECT 1}，因此不需要 RLS 请求上下文，也不受
 * {@code iam_app} 角色的行列权限影响——它证明的是"能从请求数据源的连接池里拿到一条
 * 可用连接，并在数据库侧超时预算内跑完一次往返"，而不是某张表可读。
 *
 * <p>超时不在本层设置，沿用连接层配置（application.yml）：HikariCP 获取连接 250ms，
 * JDBC {@code connectTimeout}/{@code socketTimeout} 与服务端 {@code statement_timeout}
 * 由数据源 URL 下发。语句关闭二级缓存（{@code useCache=false}），保证每次探测都真的打到库上。
 *
 * @author Acerola
 */
@Mapper
public interface HealthMapper {

    /**
     * 在当前请求数据源上执行一次最小往返探测。
     *
     * @return 数据库返回的常量：查询成功即 1；返回其它值按"探测未通过"处理（由调用方判定）
     * @throws org.springframework.dao.DataAccessException 拿不到连接、连接或语句超时、
     *         数据库报错时由 MyBatis 把 JDBC 异常翻译为 Spring 数据访问异常抛出。
     *         本方法不吞异常，降级判定交由调用方捕获
     */
    int checkConnection();
}
