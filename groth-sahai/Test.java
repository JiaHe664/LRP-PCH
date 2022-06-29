import org.apache.lucene.util.RamUsageEstimator;
import java.math.BigInteger;

public class Test{
    public static void main(String[] args){
        BigInteger a=new BigInteger("2222222222222222");
        System.out.println(RamUsageEstimator.SizeOf(a));
    }
}


