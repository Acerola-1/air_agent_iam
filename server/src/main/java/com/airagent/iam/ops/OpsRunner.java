package com.airagent.iam.ops;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.ObjectMapper;

/**
 * 命令分发与非秘密结果输出。退出码：0 成功；1 参数/运行失败；2 冲突或未完成。
 *
 * @author Acerola
 */
public class OpsRunner {

    private final OpsProperties props;
    private final OpsService service;
    private final ObjectMapper json;

    public OpsRunner(OpsProperties props, OpsService service, ObjectMapper json) {
        this.props = props;
        this.service = service;
        this.json = json;
    }

    /** 执行一次命令并返回进程退出码。 */
    public int run() {
        String command = props.getCommand() == null ? "" : props.getCommand().trim();
        if (command.isEmpty()) {
            return fail("缺少 --iam.ops.command（plan/apply/verify/inventory/cleanup-plan/cleanup-apply）", 1);
        }
        try {
            Map<String, Object> result = switch (command) {
                case "plan" -> service.planRootAccess();
                case "apply" -> service.applyRootAccess();
                case "verify" -> service.verifyRootAccess();
                case "inventory" -> service.inventoryLegacyGrants();
                case "cleanup-plan" -> service.inventoryLegacyGrants();
                case "cleanup-apply" -> service.cleanupLegacyGrants();
                default -> throw new OpsConflictException("未知命令: " + command);
            };
            emit(result);
            return exitCode(result);
        } catch (OpsConflictException e) {
            return fail(e.getMessage(), 2);
        } catch (RuntimeException e) {
            return fail(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(), 1);
        }
    }

    private int exitCode(Map<String, Object> result) {
        Object ok = result.get("ok");
        if (Boolean.FALSE.equals(ok)) {
            return 2;
        }
        Object failed = result.get("summary");
        if (failed instanceof Map<?, ?> summary && Boolean.FALSE.equals(summary.get("ok"))) {
            return 2;
        }
        return 0;
    }

    private int fail(String message, int code) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", false);
        out.put("error", message);
        emit(out);
        return code;
    }

    private void emit(Map<String, Object> result) {
        String text = json.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        System.out.println(text);
        if (props.getOutput() != null && !props.getOutput().isBlank()) {
            try {
                Path path = Path.of(props.getOutput()).toAbsolutePath();
                if (path.getParent() != null) {
                    Files.createDirectories(path.getParent());
                }
                Files.writeString(path, text + System.lineSeparator(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new IllegalStateException("结果文件写入失败: " + e.getMessage(), e);
            }
        }
    }
}
