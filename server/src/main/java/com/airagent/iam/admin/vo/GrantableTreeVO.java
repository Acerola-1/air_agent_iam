package com.airagent.iam.admin.vo;

import java.util.List;

/** HTTP 出参；普通身份视图不含口令摘要。 */
public record GrantableTreeVO(
        List<Group> groups
) {
    public record Group(String scope, String name, List<Leaf> permissions) {
    }

    public record Leaf(String code, String name, String resourceCode) {
    }
}
