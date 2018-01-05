import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.jenkinsci.plugins.palagend.jk.KeycloakSecurityRealm;
import org.jenkinsci.plugins.palagend.jk.ReflectUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.keycloak.adapters.KeycloakDeployment;

import java.io.IOException;
import java.util.UUID;

/**
 * Created by huyh on 2018/1/5.
 */
@RunWith(JUnit4.class)
public class MyTest {
    @Test
    public void test() throws IOException {
        String keycloakJson = "{\n  \"realm\": \"ci\",\n  \"auth-server-url\": \"http://keycloak.palagend.com/auth\",\n  \"ssl-required\": \"external\",\n  \"resource\": \"jenkins\",\n  \"credentials\": {\n    \"secret\": \"ff85b2ea-53cc-4053-ab4f-ea27de11b511\"\n  },\n  \"policy-enforcer\": {}\n}";
        KeycloakSecurityRealm keycloakSecurityRealm = new KeycloakSecurityRealm(keycloakJson);
        KeycloakDeployment deployment = keycloakSecurityRealm.getKeycloakDeployment();
        HttpResponse httpResponse = deployment.getClient().execute(new HttpGet("http://keycloak.palagend.com/auth/realms/ci/protocol/openid-connect/auth?client_id=jenkins&redirect_uri=http%3A%2F%2Fjenkins.palagend.com%2FsecurityRealm%2FfinishLogin&response_type=code&state=" + UUID.randomUUID().toString()));
        Object obj = httpResponse.getStatusLine();
        System.out.println(ReflectUtil.objToStr(obj));
//        String code = "xxxxx";
//        String redirect = "http://jenkins.palagend.com/securityRealm/finishLogin";
//        AccessTokenResponse tokenResponse = null;
//        try {
//            tokenResponse = ServerRequest.invokeAccessCodeToToken(deployment, code, redirect, null);
//        } catch (ServerRequest.HttpFailure failure) {
//            System.out.println(failure.getStatus() + "   " + failure.getError());
//        }
//        ReflectUtil.printWithSign("PALAGEND", tokenResponse);
    }
}
