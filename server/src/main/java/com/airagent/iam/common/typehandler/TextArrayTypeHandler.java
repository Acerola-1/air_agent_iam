package com.airagent.iam.common.typehandler;

import java.sql.Array;
import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedJdbcTypes;
import org.apache.ibatis.type.MappedTypes;

/**
 * PostgreSQL {@code text[]} 与不可变 {@code List<String>} 之间的显式类型映射。
 *
 * <p>注册为 MyBatis 全局 handler（mybatis.type-handlers-package）；读取路径以
 * {@code JdbcType.ARRAY} 且 null-jdbc 匹配，写入总是构造原生数组。结果集列恒不返回
 * {@code null}：数据库 NULL 映射为空列表。驱动数组在使用后立即 {@code free()}，
 * 避免占用连接资源。
 *
 * @author Acerola
 */
@MappedTypes(List.class)
@MappedJdbcTypes(value = JdbcType.ARRAY, includeNullJdbcType = true)
public class TextArrayTypeHandler extends BaseTypeHandler<List<String>> {

    /**
     * 将字符串列表写为 PostgreSQL text 数组参数。
     *
     * @param statement 目标预编译语句
     * @param index     参数位置（1 起）
     * @param values    非空列表（基类保证；空列表写入空数组）
     * @param jdbcType  忽略，固定按 ARRAY 写入
     * @throws SQLException 连接创建数组失败时
     */
    @Override
    public void setNonNullParameter(PreparedStatement statement, int index, List<String> values,
                                    JdbcType jdbcType) throws SQLException {
        statement.setArray(index, statement.getConnection().createArrayOf("text", values.toArray()));
    }

    /**
     * 按列名读取数组列。
     *
     * @param resultSet 当前行
     * @param column    列名
     * @return 不可变字符串列表；列为 NULL 时为空列表
     * @throws SQLException 读取或元素类型转换失败时
     */
    @Override
    public List<String> getNullableResult(ResultSet resultSet, String column) throws SQLException {
        return read(resultSet.getArray(column));
    }

    /**
     * 按列序号读取数组列（语义同列名重载）。
     *
     * @param resultSet 当前行
     * @param column    列序号（1 起）
     * @return 不可变字符串列表；列为 NULL 时为空列表
     * @throws SQLException 读取或元素类型转换失败时
     */
    @Override
    public List<String> getNullableResult(ResultSet resultSet, int column) throws SQLException {
        return read(resultSet.getArray(column));
    }

    /**
     * 从存储过程出参读取数组列（本项目当前无 CallableStatement 用法，保留通用实现）。
     *
     * @param statement 调用语句
     * @param column    参数序号（1 起）
     * @return 不可变字符串列表；NULL 时为空列表
     * @throws SQLException 读取失败时
     */
    @Override
    public List<String> getNullableResult(CallableStatement statement, int column) throws SQLException {
        return read(statement.getArray(column));
    }

    /**
     * 数组值到列表的共用转换：NULL 归一化为空列表，元素强制转 String，最后释放数组。
     *
     * @param array JDBC 数组；可为 {@code null}
     * @return 不可变列表
     * @throws SQLException {@code getArray()} 或释放时
     */
    private List<String> read(Array array) throws SQLException {
        if (array == null) {
            return List.of();
        }
        try {
            return Arrays.stream((Object[]) array.getArray()).map(String.class::cast).toList();
        } finally {
            array.free();
        }
    }
}
