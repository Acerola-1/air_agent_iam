---
version: alpha
colors:
  background: '#f5f7fa'
  text: '#1f2937'
  sidebar: '#0f172a'
  selectedNavigation: '#1d4ed8'
typography:
  sans:
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif"
omitted:
  - section: rounded
    reason: 'Inherited from the existing Element Plus theme.'
  - section: spacing
    reason: 'Existing AdminLayout and shared components own spacing.'
---

## Overview

中文企业权限管理工具。延续现有深色导航、浅色工作区和Element Plus控件，以准确展示企业归属与授权状态为主；本轮不重新设计全站。依据为`web/src/App.vue`、`web/src/layouts/AdminLayout.vue`及既有企业/成员页面。

## Colors

颜色由现有App和AdminLayout拥有，本文件记录现状，不生成第二份CSS。按钮语义色沿用Element Plus主题，不以颜色替代状态文字。

## Typography

沿用系统中文字体回退；长资源编码在表格内部滚动或折行，不能挤掉操作按钮。

## Layout

卡片列表与游标分页沿用既有布局。弹窗受视口限制，390×844仍可访问输入与底部操作。长表格自己横向滚动，不锁死整个页面。

## Elevation & Depth

数据卡片沿用shadow="never"；模态层由Element Plus管理。

## Shapes

形状由既有Element Plus主题和共享组件决定，不新增一套圆角。

## Components

列表和表单使用Element Plus；分页复用CursorPager，提示复用ElMessage与ElAlert；开通管理复用TenantEntitlementDialog，异步表单复用useWriteScope。行为见[UX-CONTRACT.md](UX-CONTRACT.md)。

## Do's and Don'ts

明确显示目标企业、资源编码、已配置与当前有效的区别。回收前说明立即失效、原配置保留及可能需要重新登录。会话/内部凭据不进入页面存储；机器密钥仅一次性展示。迟到响应不得改写新账号或新企业的表单。
