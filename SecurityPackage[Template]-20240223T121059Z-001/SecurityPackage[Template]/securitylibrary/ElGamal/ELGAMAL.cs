using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        public int power(int f, int s, int sf)
        {
            //throw new NotImplementedException();
            int res = 1;
            for (int i = 0; i < s; i++)
            {
                res = (res * f) % sf;
            }
            return res;

        }


        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            int K = power(y, k, q);
            long c1 = power(alpha, k, q);
            long c2 = (K * m) % q;
            List<long> result = new List<long>();
            result.Add(c1);
            result.Add(c2);
            return result;

        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int key = power(c1, x, q);
            ExtendedEuclid euclid = new ExtendedEuclid();
            int key_inverse = euclid.GetMultiplicativeInverse(key, q);
            int M = (c2 * key_inverse) % q;
            return M;
        }



    }
}
