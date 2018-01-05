import org.jenkinsci.plugins.palagend.jk.ReflectUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.keycloak.representations.AccessTokenResponse;

/**
 * Created by huyh on 2018/1/5.
 */
@RunWith(JUnit4.class)
public class MyTest {
    @Test
    public void test() {
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        ReflectUtil.covertToString(tokenResponse);
    }
}
