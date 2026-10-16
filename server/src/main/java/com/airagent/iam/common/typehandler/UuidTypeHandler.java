package com.airagent.iam.common.typehandler;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;

/**
 * PostgreSQL {@code uuid} 与 {@link UUID} 的显式类型映射。
 *
 * <p>经 JDBC 4.2 的对象形式直接传递（{@code setObject}/{@code getObject(…, UUID.class)}），
 * 不做字符串拼接转换；NULL 列由 JDBC 返回 {@code null}。
 *
 * @author Acerola
 */
@MappedTypes(UUID.class)
public class UuidTypeHandler extends BaseTypeHandler<UUID> {

    /**
     * 写入 UUID 参数。
     *
     * @param statement 目标预编译语句
     * @param index     参数位置（1 起）
     * @param value     非空 UUID（基类保证）
     * @param jdbcType  忽略，驱动按 uuid 类型推断
     * @throws SQLException 驱动拒绝该对象类型时
     */
    @Override
    public void setNonNullParameter(PreparedStatement statement, int index, UUID value,
                                    JdbcType jdbcType) throws SQLException {
        statement.setObject(index, value);
    }

    /**
     * 按列名读取 UUID 列。
     *
     * @param resultSet 当前行
     * @param column    列名
     * @return UUID；列为 NULL 时 {@code null}
     * @throws SQLException 读取失败时
     */
    @Override
    public UUID getNullableResult(ResultSet resultSet, String column) throws SQLException {
        return resultSet.getObject(column, UUID.class);
    }

    /**
     * 按列序号读取 UUID 列（语义同列名重载）。
     *
     * @param resultSet 当前行
     * @param column    列序号（1 起）
     * @return UUID；列为 NULL 时 {@code null}
     * @throws SQLException 读取失败时
     */
    @Override
    public UUID getNullableResult(ResultSet resultSet, int column) throws SQLException {
        return resultSet.getObject(column, UUID.class);
    }

    /**
     * 从存储过程出参读取 UUID（本项目当前未使用，保留通用实现）。
     *
     * @param statement 调用语句
     * @param column    参数序号（1 起）
     * @return UUID 或 {@code null}
     * @throws SQLException 读取失败时
     */
    @Override
    public UUID getNullableResult(CallableStatement statement, int column) throws SQLException {
        return statement.getObject(column, UUID.class);
    }
}
