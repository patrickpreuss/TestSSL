import net.continuumsecurity.utils.HeartBleedTester;
import net.continuumsecurity.utils.TestResult;
import org.junit.Test;

import java.io.IOException;

/**
 * Created by stephen on 13/04/2014.
 */
public class TestHeartbleedTester {
    public static final String vulnTarget = "www.cloudflarechallenge.com";
    public static final String patchedTarget = "www.theatlantic.com";

    @Test
    public void testAgainstVulnerableServer() throws IOException {
        HeartBleedTester tester = new HeartBleedTester();
        TestResult result = tester.test(vulnTarget,443);
        assert result.isVulnerable() == true;
        assert result.getDetails().length() > 1;
        System.out.println("Result.details: "+result.getDetails());
    }

    @Test
    public void testAgainstPatchedServer() {
        HeartBleedTester tester = new HeartBleedTester();
        TestResult result = tester.test(patchedTarget,443);
        assert result.isVulnerable() == false;
        assert result.getDetails() == null;
    }

}
