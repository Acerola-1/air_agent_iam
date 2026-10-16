package com.airagent.iam.health.mapper;

import org.apache.ibatis.annotations.Mapper;

/**
 * PostgreSQL 连接探测。
 */
@Mapper
public interface HealthMapper {

    /**
     * 在当前数据源执行连接探测。
     *
     * @return 数据库返回的常量
     */
    int checkConnection();
}
