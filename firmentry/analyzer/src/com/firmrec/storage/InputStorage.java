package com.firmrec.storage;

import java.sql.*;
import java.util.Properties;

public class InputStorage {

    private Connection conn;

    public InputStorage(String user, String password, String db) throws SQLException {
        String url = "jdbc:postgresql://localhost/" + db;
        Properties props = new Properties();
        props.setProperty("user", user);
        props.setProperty("password", password);
        props.setProperty("sslmode", "require");
        conn = DriverManager.getConnection(url, props);
    }

    public long addBin(String vendor, String firmware_id, String path, String hash, long base_addr)
            throws SQLException {
        String sql = "INSERT INTO bin(vendor, firmware_id, path, hash, base_addr) VALUES(?, ?, ?, ?, ?) ON CONFLICT (vendor, firmware_id, path) DO UPDATE SET base_addr=EXCLUDED.base_addr";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, vendor);
        pstmt.setString(2, firmware_id);
        pstmt.setString(3, path);
        pstmt.setString(4, hash);
        pstmt.setLong(5, base_addr);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }

    public long addFunc(long bin_id, long address, String name, String extra_info) throws SQLException {
        String sql = "INSERT INTO func(bin_id, address, name, extra_info) VALUES(?, ?, ?, ?) ON CONFLICT (bin_id, address) DO UPDATE SET extra_info=EXCLUDED.extra_info";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setLong(1, bin_id);
        pstmt.setLong(2, address);
        pstmt.setString(3, name);
        pstmt.setString(4, extra_info);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }

    public long addFuncCall(long caller, long callee) throws SQLException {
        String sql = "INSERT INTO func_call(caller, callee) VALUES(?, ?) ON CONFLICT (caller, callee) DO NOTHING";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setLong(1, caller);
        pstmt.setLong(2, callee);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }

    public long addFuncString(long func_id, long address, String string) throws SQLException {
        /*
         * id BIGSERIAL PRIMARY KEY,
         * func_id BIGINT REFERENCES func(id) NOT NULL,
         * address BIGINT NOT NULL,
         * string TEXT NOT NULL,
         * UNIQUE (func_id, address, string)
         */
        String sql = "INSERT INTO func_string(func_id, address, string) VALUES(?, ?, ?) ON CONFLICT (func_id, address, string) DO NOTHING";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setLong(1, func_id);
        pstmt.setLong(2, address);
        pstmt.setString(3, string);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }

    public long addInput(long bin_id, long api_id, long caller, long address, String keyword, String model)
            throws SQLException {
        String sql = "INSERT INTO input(bin_id, api_id, caller, address, keyword, model) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT (bin_id, address) DO UPDATE SET keyword=EXCLUDED.keyword, model=EXCLUDED.model";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setLong(1, bin_id);
        pstmt.setLong(2, api_id);
        pstmt.setLong(3, caller);
        pstmt.setLong(4, address);
        pstmt.setString(5, keyword);
        pstmt.setString(6, model);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getLong(1);
        }
        return -1;
    }

    public long addInputDataflowCall(String type, long input_id, long address, long func_id, int arg, String func_args)
            throws SQLException {
        String sql = "INSERT INTO input_dataflow_call(type, input_id, address, func_id, arg, func_args) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT (type, input_id, address, arg) DO UPDATE SET func_id=EXCLUDED.func_id, func_args=EXCLUDED.func_args";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, type);
        pstmt.setLong(2, input_id);
        pstmt.setLong(3, address);
        pstmt.setLong(4, func_id);
        pstmt.setInt(5, arg);
        pstmt.setString(6, func_args);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }

    public long addInputDataflowConst(String type, long input_id, long address, String constant) throws SQLException {
        String sql = "INSERT INTO input_dataflow_const(type, input_id, address, const) VALUES(?, ?, ?, ?) ON CONFLICT (type, input_id, address, const) DO UPDATE SET const=EXCLUDED.const";
        PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, type);
        pstmt.setLong(2, input_id);
        pstmt.setLong(3, address);
        pstmt.setString(4, constant);
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            return rs.getInt(1);
        }
        return -1;
    }
}
