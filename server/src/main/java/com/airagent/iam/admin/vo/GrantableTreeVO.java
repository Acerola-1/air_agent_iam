package com.airagent.iam.admin.vo;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * 当前主体可授权限树 HTTP 出参（VO，对外响应模型）。
 *
 * <p>供角色编辑器渲染"能给角色勾哪些权限"：按 scope 分组，组内是可授予的权限叶子。
 * 与权限目录（{@link PermissionVO}）的区别在于这里按"操作者能授给别人什么"过滤——
 * 非 {@code platform_super_admin} 的主体只会看到自身已具备的码，组内因此可能为空数组。
 * 资源型权限（resource_code 非空）在资源开通（I1a）之前整组缺席，数据库触发器同时硬拒其授予。
 *
 * @param groups 分组列表，顺序固定：平台口径主体为「平台权限、企业权限」两组，
 *               仅企业口径主体只有「企业权限」一组；两口径都不具备时接口直接 403，
 *               因此该列表不会为空
 * @author Acerola
 */
@Schema(description = "可授权限树（按 scope 分组的权限叶子）")
public record GrantableTreeVO(
        @Schema(description = "权限分组；平台口径主体含平台组与企业组，企业口径主体仅含企业组",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<Group> groups
) {

    /**
     * 可授权限树的一个 scope 分组。
     *
     * @param scope        分组域，仅 {@code platform} / {@code tenant}；企业角色只能装配 tenant 分组的叶子
     * @param name         分组中文名，服务端固定文案（{@code 平台权限} / {@code 企业权限}）
     * @param permissions  组内可授叶子，按目录排序号与权限码升序；操作者无可授码时为空数组
     * @author Acerola
     */
    @Schema(description = "可授权限分组（按 scope）")
    public record Group(
            @Schema(description = "分组域", requiredMode = Schema.RequiredMode.REQUIRED,
                    allowableValues = {"platform", "tenant"})
            String scope,
            @Schema(description = "分组中文名（平台权限/企业权限）", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "组内可授权限叶子，可为空数组", requiredMode = Schema.RequiredMode.REQUIRED)
            List<Leaf> permissions
    ) {
    }

    /**
     * 可授权限分组中的一个权限叶子。
     *
     * @param code           权限码（授予角色时提交的就是它），形如 {@code tenant:member:read}
     * @param name           权限中文名（对应目录的 name_zh 列）
     * @param resourceCode   资源型权限的资源标识；非资源权限为 {@code null}
     * @param resourceNameZh 资源中文名；非资源权限为 {@code null}
     * @author Acerola
     */
    @Schema(description = "可授权限叶子")
    public record Leaf(
            @Schema(description = "权限码，装配角色权限时提交的取值", requiredMode = Schema.RequiredMode.REQUIRED)
            String code,
            @Schema(description = "权限中文名", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "资源标识；非资源权限为 null")
            String resourceCode,
            @Schema(description = "资源中文名；非资源权限为 null")
            String resourceNameZh
    ) {
    }
}
