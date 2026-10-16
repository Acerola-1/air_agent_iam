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

/** PostgreSQL text[] 到不可变字符串列表，读取后释放驱动数组。 */
@MappedTypes(List.class)
@MappedJdbcTypes(value = JdbcType.ARRAY, includeNullJdbcType = true)
public class TextArrayTypeHandler extends BaseTypeHandler<List<String>> {

    @Override
    public void setNonNullParameter(PreparedStatement statement, int index, List<String> values,
                                    JdbcType jdbcType) throws SQLException {
        statement.setArray(index, statement.getConnection().createArrayOf("text", values.toArray()));
    }

    @Override
    public List<String> getNullableResult(ResultSet resultSet, String column) throws SQLException {
        return read(resultSet.getArray(column));
    }

    @Override
    public List<String> getNullableResult(ResultSet resultSet, int column) throws SQLException {
        return read(resultSet.getArray(column));
    }

    @Override
    public List<String> getNullableResult(CallableStatement statement, int column) throws SQLException {
        return read(statement.getArray(column));
    }

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
