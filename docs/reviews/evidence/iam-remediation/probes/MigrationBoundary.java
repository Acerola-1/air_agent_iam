import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/** Independent migration runner: credentials arrive through stdin, never process arguments. */
public final class MigrationBoundary {
    public static void main(String[] args) throws Exception {
        var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String url = input.readLine();
        String user = input.readLine();
        String password = input.readLine();
        String location = input.readLine();
        var configuration = Flyway.configure().dataSource(url, user, password)
                .schemas("iam_auth", "iam").defaultSchema("iam").locations(location)
                .createSchemas(true).validateOnMigrate(true);
        if (!args[0].equals("latest")) {
            configuration.target(MigrationVersion.fromVersion(args[0]));
        }
        var result = configuration.load().migrate();
        System.out.println("MIGRATION_OK " + result.migrationsExecuted);
    }
}
