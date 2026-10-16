import com.airagent.iam.security.password.PasswordHasher;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
public class IndependentBcrypt {
    public static void main(String[] args) throws Exception {
        var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String mode = reader.readLine();
        String password = new String(Base64.getDecoder().decode(reader.readLine()), StandardCharsets.UTF_8);
        var hasher = new PasswordHasher();
        if (mode.equals("hash")) System.out.println(hasher.hash(password));
        else System.out.println(hasher.matches(password, reader.readLine()));
    }
}
