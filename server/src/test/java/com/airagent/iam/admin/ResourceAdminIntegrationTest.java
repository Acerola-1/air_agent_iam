package com.airagent.iam.admin;

import com.airagent.iam.security.password.PasswordHasher;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;

/** 真实PG/Redis上的资源授权回归：公开管理链、旧上下文、分页与受限角色防护。 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
class ResourceAdminIntegrationTest {
    private static final String PASSWORD = "Resource-It-Only-123!";
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired PasswordHasher hasher;
    @Value("${spring.flyway.url}") String ownerUrl;
    @Value("${spring.flyway.user}") String ownerUser;
    @Value("${spring.flyway.password}") String ownerPassword;
    @Value("${spring.datasource.url}") String appUrl;
    @Value("${spring.datasource.username}") String appUser;
    @Value("${spring.datasource.password}") String appPassword;
    private String root;
    private JsonNode rootIdentity;

    @BeforeEach
    void seedOwnedTestDatabase() throws Exception {
        try (var c = DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword); var st = c.createStatement()) {
            st.execute("TRUNCATE iam.resource_catalog,iam.internal_clients,iam.tenants,iam.users,iam.auth_sessions,iam.audit_logs,iam.outbox,iam.sso_clients,iam.browser_handles,iam.bootstrap_meta CASCADE");
            c.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context(NULL,NULL,true)");
            st.execute("INSERT INTO iam.resource_catalog(code,name_zh,sort,status,kind,parent_code) VALUES ('knowledge:lib:air','空气知识库',10,'active','leaf','knowledge') ON CONFLICT (code) DO NOTHING");
            st.execute(new String(new ClassPathResource("db/migration/V2__seed_catalog.sql").getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            st.execute("INSERT INTO iam.permissions(id,code,name_zh,scope,grantable_to_tenants,sort) VALUES ('01930000-0000-4000-8000-000000000211','tenant:resource:grant','企业资源授权管理','tenant',true,211)");
            st.execute("INSERT INTO iam.role_permissions(role_id,permission_id) SELECT r.id,p.id FROM iam.roles r JOIN iam.permissions p ON p.code='tenant:resource:grant' WHERE r.code='tenant_admin'");
            try (var ps = c.prepareStatement("SELECT iam_auth.ensure_bootstrap_user(?,?,?,?)")) {
                ps.setString(1,"resource.it.root"); ps.setString(2,"资源测试管理员"); ps.setString(3,hasher.hash(PASSWORD));
                ps.setObject(4,UUID.fromString("01930000-0000-4000-8000-000000000301")); ps.execute();
            }
            c.commit();
        }
        JsonNode login = login("resource.it.root"); root=login.path("access_token").asText();rootIdentity=login.path("identity");
    }

    @Test
    void firstGrantMixedPermissionsMemberFlowAndInactiveConfiguration() throws Exception {
        Scenario f = scenario();
        var body = resourceRole(f,"mixed_reader");
        body.put("permission_codes",List.of("knowledge:lib:it:read","tenant:member:read"));
        JsonNode role=call("POST","/v1/admin/roles",body,f.adminToken,201);
        JsonNode member=call("POST","/v1/admin/members",Map.of("account","it-resource-member","display_name","资源成员","password",PASSWORD,"role_codes",List.of("mixed_reader"),"expected_context",context(f.adminIdentity),"expected_tenant_revision",f.revision),f.adminToken,201);
        String memberToken=login("it-resource-member").path("access_token").asText();
        call("POST","/v1/auth/switch-tenant",Map.of("tenant_id",f.tenant,"expected_ctx_version",1),memberToken,200);
        JsonNode me=call("GET","/v1/auth/me",null,memberToken,200);
        assertTrue(me.path("permissions").toString().contains("knowledge:lib:it:read"));
        JsonNode revoked=call("PUT","/v1/admin/tenants/"+f.tenant+"/entitlements/knowledge:lib:it",Map.of("expected_context",context(rootIdentity),"expected_revision",1,"expected_tenant_revision",f.revision,"status","revoked"),root,200);
        assertTrue(revoked.path("changed").asBoolean());
        call("GET","/v1/auth/me",null,memberToken,401);
        JsonNode freshLogin=login("it-resource-admin");String admin=freshLogin.path("access_token").asText();
        JsonNode identity=call("POST","/v1/auth/switch-tenant",Map.of("tenant_id",f.tenant,"expected_ctx_version",1),admin,200);
        JsonNode list=call("GET","/v1/admin/roles?scope=tenant",null,admin,200);
        JsonNode current=null;
        for(JsonNode row:list.path("items"))if(row.path("id").asText().equals(role.path("id").asText()))current=row;
        assertNotNull(current);
        for(JsonNode state:current.path("permission_states"))if(state.path("code").asText().equals("knowledge:lib:it:read")) {
            assertFalse(state.path("effective").asBoolean()); assertFalse(state.path("grantable").asBoolean());
        }
        call("POST","/v1/admin/roles/"+role.path("id").asText()+"/permissions",Map.of("permission_codes",List.of("knowledge:lib:it:read","tenant:member:read"),"expected_context",context(identity),"expected_tenant_revision",revoked.path("tenant_auth_revision").asLong()),admin,200);
        assertNotNull(member.path("id").asText());
    }

    @Test
    void resourceWritesRejectMissingStaleContextAndTenantRevision() throws Exception {
        Scenario f=scenario();
        Map<String,Object> missing=resourceRole(f,"missing_context");missing.remove("expected_context");
        call("POST","/v1/admin/roles",missing,f.adminToken,400);
        Map<String,Object> stale=resourceRole(f,"stale_context");
        Map<String,Object> ctx=new LinkedHashMap<>(context(f.adminIdentity));ctx.put("session_id",UUID.randomUUID().toString());stale.put("expected_context",ctx);
        call("POST","/v1/admin/roles",stale,f.adminToken,409);
        Map<String,Object> revision=resourceRole(f,"bad_revision");revision.put("expected_tenant_revision",0);
        call("POST","/v1/admin/roles",revision,f.adminToken,409);
        JsonNode rows=call("GET","/v1/admin/roles?scope=tenant",null,f.adminToken,200);
        for(JsonNode row:rows.path("items"))assertFalse(row.path("code").asText().matches("missing_context|stale_context|bad_revision"));
    }

    @Test
    void sortedPaginationStrictJsonAndMissingTenant() throws Exception {
        for(var entry:Map.of("dataset:zz",-10,"dataset:mm",0,"dataset:aa",20).entrySet())createResource(entry.getKey(),entry.getValue());
        List<String> seen=new ArrayList<>();String cursor=null;
        do {
            JsonNode page=call("GET","/v1/admin/resources?limit=1"+(cursor==null?"":"&cursor="+cursor),null,root,200);
            for(JsonNode item:page.path("items"))seen.add(item.path("code").asText());
            cursor=page.path("next_cursor").isNull()?null:page.path("next_cursor").asText();
            assertTrue(seen.size()<=4,"分页不得重复或成环");
        } while(cursor!=null);
        assertEquals(4,seen.size());assertEquals(4,seen.stream().distinct().count());assertEquals("dataset:zz",seen.getFirst());
        call("GET","/v1/admin/resources?status=bogus",null,root,400);
        call("GET","/v1/admin/tenants/"+UUID.randomUUID()+"/entitlements",null,root,404);
        Map<String,Object> bad=new LinkedHashMap<>();bad.put("expected_context",context(rootIdentity));bad.put("code","dataset:bad");bad.put("name_zh","错误");bad.put("permissions",java.util.Arrays.asList((Object)null));
        call("POST","/v1/admin/resources",bad,root,400);
        bad.put("permissions",List.of(Map.of("code","dataset:bad:read","name_zh","读","grantable_to_tenants",true)));bad.put("unknown",true);
        call("POST","/v1/admin/resources",bad,root,400);
    }

    @Test
    void dualMemberRoleListIsLimitedToCurrentTenantBeforePagination() throws Exception {
        Scenario f=scenario();
        call("POST","/v1/admin/roles",Map.of("scope","tenant","code","only_a","name","A角色","permission_codes",List.of()),f.adminToken,201);
        String userId=f.adminIdentity.path("user").path("id").asText();
        JsonNode b=call("POST","/v1/admin/tenants",Map.of("code","SECOND-IT","name","第二企业","initial_admin_user_id",userId),root,201);
        JsonNode fresh=login("it-resource-admin");String token=fresh.path("access_token").asText();
        JsonNode current=fresh.path("identity");
        JsonNode inB=call("POST","/v1/auth/switch-tenant",Map.of("tenant_id",b.path("id").asText(),"expected_ctx_version",current.path("session").path("ctx_version").asLong()),token,200);
        call("POST","/v1/admin/roles",Map.of("scope","tenant","code","only_b","name","B角色","permission_codes",List.of()),token,201);
        call("POST","/v1/auth/switch-tenant",Map.of("tenant_id",f.tenant,"expected_ctx_version",inB.path("session").path("ctx_version").asLong()),token,200);
        List<String> codes=new ArrayList<>();String cursor=null;
        do {
            JsonNode page=call("GET","/v1/admin/roles?scope=tenant&limit=1"+(cursor==null?"":"&cursor="+cursor),null,token,200);
            for(JsonNode row:page.path("items")) {
                assertTrue(row.path("tenant_id").isNull()||row.path("tenant_id").asText().equals(f.tenant));
                codes.add(row.path("code").asText());
            }
            cursor=page.path("next_cursor").isNull()?null:page.path("next_cursor").asText();
            assertTrue(codes.size()<10);
        }while(cursor!=null);
        assertTrue(codes.contains("only_a"));assertFalse(codes.contains("only_b"));
        JsonNode implicit=call("GET","/v1/admin/roles",null,token,200);
        for(JsonNode row:implicit.path("items"))assertEquals("tenant",row.path("scope").asText());
        call("GET","/v1/admin/roles?scope=platform",null,token,403);
    }

    @Test
    void requestRoleCannotDeleteOrSelfOpenEntitlements() throws Exception {
        Scenario f=scenario();
        try(var c=DriverManager.getConnection(appUrl,appUser,appPassword);var st=c.createStatement()) {
            c.setAutoCommit(false);
            st.execute("SELECT iam_auth.set_request_context('"+f.adminIdentity.path("user").path("id").asText()+"','"+f.tenant+"',false)");
            assertEquals(0,st.executeUpdate("DELETE FROM iam.tenant_entitlements WHERE tenant_id='"+f.tenant+"'"));
            c.rollback();
        }
    }

    private Scenario scenario() throws Exception {
        JsonNode user=call("POST","/v1/admin/users",Map.of("account","it-resource-admin","display_name","企业管理员","password",PASSWORD),root,201);
        JsonNode tenant=call("POST","/v1/admin/tenants",Map.of("code","RESOURCE-IT","name","资源企业","initial_admin_user_id",user.path("id").asText()),root,201);
        createResource("knowledge:lib:it",0);
        JsonNode ent=call("PUT","/v1/admin/tenants/"+tenant.path("id").asText()+"/entitlements/knowledge:lib:it",Map.of("expected_context",context(rootIdentity),"expected_revision",0,"expected_tenant_revision",tenant.path("auth_revision").asLong(),"status","active"),root,200);
        String token=login("it-resource-admin").path("access_token").asText();
        JsonNode identity=call("POST","/v1/auth/switch-tenant",Map.of("tenant_id",tenant.path("id").asText(),"expected_ctx_version",1),token,200);
        assertFalse(identity.path("permissions").toString().contains("knowledge:lib:it:read"));
        return new Scenario(tenant.path("id").asText(),token,identity,ent.path("tenant_auth_revision").asLong());
    }
    private Map<String,Object> resourceRole(Scenario f,String code) {
        return new LinkedHashMap<>(Map.of("scope","tenant","code",code,"name","资源角色","permission_codes",List.of("knowledge:lib:it:read"),"expected_context",context(f.adminIdentity),"expected_tenant_revision",f.revision));
    }
    private void createResource(String code,int sort) throws Exception {
        call("POST","/v1/admin/resources",Map.of("expected_context",context(rootIdentity),"code",code,"name_zh",code,"sort",sort,"permissions",List.of(Map.of("code",code+":read","name_zh","读取","grantable_to_tenants",true))),root,201);
    }
    private JsonNode login(String account) throws Exception {
        return call("POST","/v1/auth/login",Map.of("account",account,"password",PASSWORD,"realm","workforce","audience","iam-admin"),null,200);
    }
    private Map<String,Object> context(JsonNode identity) {
        Map<String,Object> ctx=new LinkedHashMap<>();ctx.put("session_id",identity.path("session").path("id").asText());ctx.put("tenant_id",identity.path("current_tenant").isNull()?null:identity.path("current_tenant").path("id").asText());ctx.put("ctx_version",identity.path("session").path("ctx_version").asLong());return ctx;
    }
    private JsonNode call(String method,String path,Object body,String token,int status) throws Exception {
        var request=MockMvcRequestBuilders.request(org.springframework.http.HttpMethod.valueOf(method),path).contentType(MediaType.APPLICATION_JSON);
        if(token!=null)request.header("Authorization","Bearer "+token);
        if(body!=null)request.content(json.writeValueAsString(body));
        var result=mvc.perform(request).andReturn();
        assertEquals(status,result.getResponse().getStatus(),method+" "+path+" "+result.getResponse().getContentAsString());
        return json.readTree(result.getResponse().getContentAsString());
    }
    private record Scenario(String tenant,String adminToken,JsonNode adminIdentity,long revision) { }
}
