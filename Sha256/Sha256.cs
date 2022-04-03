namespace Sha256Learning
{
    public class Sha256
    {
        private const uint constH0 = 0x6a09e667;
        private const uint constH1 = 0xbb67ae85;
        private const uint constH2 = 0x3c6ef372;
        private const uint constH3 = 0xa54ff53a;
        private const uint constH4 = 0x510e527f;
        private const uint constH5 = 0x9b05688c;
        private const uint constH6 = 0x1f83d9ab;
        private const uint constH7 = 0x5be0cd19;

        static readonly uint[] k =
        {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        public byte[] Encode(byte[] data)
        {           var dataLength = data.Length;
            var preparedDataLength = dataLength + 1;
            var dif = preparedDataLength % 64;
            var filler = (dif <= 56) ? 56 - dif : 56 + (64 - dif);
            preparedDataLength = preparedDataLength + filler + 8;
            var preparedData = new byte[preparedDataLength];

            for (var i = 0; i < dataLength; i++)
            {
                preparedData[i] = data[i];
            }
            //set end bit
            preparedData[dataLength] = 128;

            ulong size = (ulong)dataLength * 8;
            for (var i = 8; i > 0; i--)
            {
                preparedData[(preparedDataLength - 9) + i] = (byte)(size & 255);
                size = size >> 8;
            }

            uint h0 = constH0; //0x6a09e667;
            uint h1 = constH1; //xbb67ae85;
            uint h2 = constH2; //x3c6ef372;
            uint h3 = constH3; //xa54ff53a;
            uint h4 = constH4; //x510e527f;
            uint h5 = constH5; //x9b05688c;
            uint h6 = constH6; //x1f83d9ab;
            uint h7 = constH7; //0x5be0cd19;

            //blocks by 512 bit
            for (var blockIndex = 0; blockIndex < preparedDataLength; blockIndex += 64)
            {
                var words = new uint[64];
                //16 words by 32 bit
                for (var wordIndex = 0; wordIndex <= 15; wordIndex++)
                {
                    var preparedDataPointer = (wordIndex * 4) + blockIndex;
                    words[wordIndex] =
                        ((uint)preparedData[preparedDataPointer + 3 ]) |
                        (((uint)preparedData[preparedDataPointer + 2]) << 8) |
                        (((uint)preparedData[preparedDataPointer + 1]) << 16) |
                        (((uint)preparedData[preparedDataPointer]) << 24);
                }
                //generate additional 48 words
                for (var i = 16; i <= 63; i++)
                {
                    var s0 = RotateRight(words[i - 15], 7) ^ RotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3);
                    var s1 = RotateRight(words[i - 2], 17) ^ RotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10);
                    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
                }

                //initializa helpers
                var a = h0;
                var b = h1;
                var c = h2;
                var d = h3;
                var e = h4;
                var f = h5;
                var g = h6;
                var h = h7;

                //
                for (var i = 0; i < 64; i++)
                {
                    var Σ0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
                    var Ma = (a & b) ^ (a & c) ^ (b & c);
                    var t2 = Σ0 + Ma;
                    var Σ1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
                    var Ch = (e & f) ^ ((~e) & g);
                    var t1 = h + Σ1 + Ch + k[i] + words[i];

                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                h0 = h0 + a;
                h1 = h1 + b;
                h2 = h2 + c;
                h3 = h3 + d;
                h4 = h4 + e;
                h5 = h5 + f;
                h6 = h6 + g;
                h7 = h7 + h;
            }

            var hash = Concat(h0, h1, h2, h3, h4, h5, h6, h7);

            return hash;
        }

        private byte[] Concat(params uint[] h)
        {
            var result = new byte[32];

            for (var i = 0; i < 8; i++)
            {
                result[i * 4] = (byte)((h[i] >> 24) & 255);
                result[i * 4 + 1] = (byte)((h[i] >> 16) & 255);
                result[i * 4 + 2] = (byte)((h[i] >> 8) & 255);
                result[i * 4 + 3] = (byte)(h[i] & 255);
            }

            return result;
        }

        private uint RotateRight(uint value, int n)
        {
            return (value >> n) | value << (32 - n);
        }

        //private uint RotateLeft(uint value, int n)
        //{
        //    return (value << n) | value >> (32 - n);
        //}
    }
}
