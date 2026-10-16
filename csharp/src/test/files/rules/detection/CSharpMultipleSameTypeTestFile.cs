/*
 * Several calls of the same kind inside one method.
 *
 * This used to lose every parameter but the first: the C# dispatch created one DetectionExecutive
 * per method body, so all matching calls in the body shared a single root DetectionStore, and a
 * store holds the parameters of one call. Java and Python dispatch per call site and were never
 * affected. The curves below must therefore come out individually, and the single-call methods at
 * the bottom are the control group that was already correct before.
 */

using System.Security.Cryptography;

namespace Testing
{
    public class MultipleSameType
    {
        public void ThreeCurvesInOneMethod()
        {
            var a = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var b = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            var c = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        }

        public void ThreeKeySizesInOneMethod()
        {
            var a = RSA.Create(2048);
            var b = RSA.Create(3072);
            var c = RSA.Create(4096);
        }

        public void MixedWithAnUnparameterisedCall()
        {
            var a = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var b = ECDsa.Create();
            var c = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        }

        public void SingleCurveA()
        {
            var a = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        public void SingleCurveB()
        {
            var b = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        }
    }
}
