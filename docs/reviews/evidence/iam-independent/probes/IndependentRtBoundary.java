import com.airagent.iam.security.rt.RtV1Body;
import com.airagent.iam.security.rt.RtV1Codec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class IndependentRtBoundary {
    public static void main(String[] args) throws Exception {
        var input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String mode = input.readLine();
        String kid = input.readLine();
        byte[] secret = input.readLine().getBytes(StandardCharsets.UTF_8);
        String audience = input.readLine();
        long now = Long.parseLong(input.readLine());
        if (mode.equals("verify")) {
            var result = RtV1Codec.verify(input.readLine(), kid, secret, audience, now);
            System.out.println("{\"ok\":" + result.ok() + ",\"reason\":\"" + result.reason() + "\"}");
        } else if (mode.equals("sign")) {
            var body = new RtV1Body(
                UUID.fromString("95b48e1e-7c1d-46fd-b1d7-cfb04b31ac01"),
                UUID.fromString("95b48e1e-7c1d-46fd-b1d7-cfb04b31ac02"),
                UUID.fromString("95b48e1e-7c1d-46fd-b1d7-cfb04b31ac03"),
                UUID.fromString("95b48e1e-7c1d-46fd-b1d7-cfb04b31ac04"),
                audience, now, now + 60, 3, 5, 7, 11);
            System.out.println(RtV1Codec.sign(body, kid, secret));
        } else {
            throw new IllegalArgumentException("Unknown probe mode");
        }
    }
}
