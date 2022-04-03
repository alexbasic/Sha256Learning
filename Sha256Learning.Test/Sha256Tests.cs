using NUnit.Framework;
using System;
using System.Text;

namespace Sha256Learning.Test
{
    public class Sha256Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        [TestCase("", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")]
        [TestCase("a", "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB")]
        [TestCase("The quick brown fox jumps over the lazy dog", "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592")]
        public void ComputeHashForStringTest(string input, string expectedResult)
        {
            var encoder = new Sha256();
            var inputAsBytes = Encoding.UTF8.GetBytes(input);
            var binaryHash = encoder.Encode(inputAsBytes);
            var result = Convert.ToHexString(binaryHash);

            Assert.AreEqual(expectedResult, result);
        }

        [TestCase("", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")]
        [TestCase("a", "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB")]
        [TestCase("The quick brown fox jumps over the lazy dog", "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592")]
        public void TheReference(string input, string expectedResult)
        {
            var inputAsBytes = Encoding.UTF8.GetBytes(input);
            var binaryHash = System.Security.Cryptography.SHA256.HashData(inputAsBytes);
            var result = Convert.ToHexString(binaryHash);
            
            Assert.AreEqual(expectedResult, result);
        }
    }
}