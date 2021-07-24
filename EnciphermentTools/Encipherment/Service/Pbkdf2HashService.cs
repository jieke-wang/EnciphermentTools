using EnciphermentTools.Encipherment.Interface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnciphermentTools.Encipherment.Service
{
    public class Pbkdf2HashService : IPbkdf2HashService
    {
        private int Iterations { get; set; }
        private readonly HMAC _hmac;
        private readonly byte[] _saltBytes;

        private readonly int _blockSize;
        private uint _blockIndex = 1;
        private byte[] _bufferBytes;
        private int _bufferStartIndex;
        private int _bufferEndIndex;

        #region Private Methods

        private byte[] Func()
        {
            var hash1Input = new byte[_saltBytes.Length + 4];

            Buffer.BlockCopy(_saltBytes, 0, hash1Input, 0, _saltBytes.Length);
            Buffer.BlockCopy(GetBytesFromInt(_blockIndex), 0, hash1Input, _saltBytes.Length, 4);

            var hash1 = _hmac.ComputeHash(hash1Input);

            byte[] finalHash = hash1;

            for (int i = 2; i <= Iterations; i++)
            {
                hash1 = _hmac.ComputeHash(hash1, 0, hash1.Length);

                for (int j = 0; j < _blockSize; j++)
                {
                    finalHash[j] = (byte)(finalHash[j] ^ hash1[j]);
                }
            }

            if (_blockIndex == uint.MaxValue) { throw new InvalidOperationException("Derived key too long."); }
            _blockIndex += 1;

            return finalHash;
        }

        private static byte[] GetBytesFromInt(uint i)
        {
            var bytes = BitConverter.GetBytes(i);
            return BitConverter.IsLittleEndian ? new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] } : bytes;
        }

        #endregion

        public Pbkdf2HashService(string password, byte[] saltBytes, int iterations = 1000, string algorithm = "System.Security.Cryptography.HMACSHA256")
        {
            Iterations = iterations;

            _hmac = HMAC.Create(algorithm);
            _hmac.Key = Encoding.UTF8.GetBytes(password);

            _blockSize = _hmac.HashSize / 8;
            _bufferBytes = new byte[_blockSize];
            _saltBytes = saltBytes;
        }

        public Byte[] GetBytes(int count)
        {
            var result = new byte[count];
            var resultOffset = 0;
            var bufferCount = _bufferEndIndex - _bufferStartIndex;

            if (bufferCount > 0)
            {
                if (count < bufferCount)
                {
                    Buffer.BlockCopy(_bufferBytes, _bufferStartIndex, result, 0, count);
                    _bufferStartIndex += count;

                    return result;
                }

                Buffer.BlockCopy(_bufferBytes, _bufferStartIndex, result, 0, bufferCount);
                _bufferStartIndex = _bufferEndIndex = 0;

                resultOffset += bufferCount;
            }

            while (resultOffset < count)
            {
                var needCount = count - resultOffset;
                _bufferBytes = Func();

                if (needCount > _blockSize)
                {
                    Buffer.BlockCopy(_bufferBytes, 0, result, resultOffset, _blockSize);
                    resultOffset += _blockSize;
                }
                else
                {
                    Buffer.BlockCopy(_bufferBytes, 0, result, resultOffset, needCount);
                    _bufferStartIndex = needCount;
                    _bufferEndIndex = _blockSize;

                    return result;
                }
            }

            return result;
        }
    }
}
