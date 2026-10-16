import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.flywaydb.core.Flyway;
public class IndependentMigration {
 public static void main(String[] args) throws Exception {
  var in=new BufferedReader(new InputStreamReader(System.in));
  var f=Flyway.configure().dataSource(in.readLine(),in.readLine(),in.readLine())
    .schemas("iam","iam_auth").defaultSchema("iam").locations("filesystem:"+in.readLine())
    .target(in.readLine()).load();
  var result=f.migrate();System.out.println("INDEPENDENT_MIGRATIONS_EXECUTED="+result.migrationsExecuted);
 }
}
