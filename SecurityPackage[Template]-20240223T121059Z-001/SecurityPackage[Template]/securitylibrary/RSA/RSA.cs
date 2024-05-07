using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();

            int n = p * q;
            int c = power(M, e, n);
            return c;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phiN = (p - 1) * (q - 1);
            int MI = MultiInverse(e, phiN);

            if (MI == -1)
            {
                return -1;
            }

            long res = 1;
            long baseValue = C % n;
            int exp = MI;

            while (exp > 0)
            {
                if (exp % 2 == 1)
                    res = (res * baseValue) % n;

                baseValue = (baseValue * baseValue) % n;
                exp /= 2;
            }

            return (int)res;
        }

        private int MultiInverse(int number, int baseN)
        {
            int originalBaseN = baseN;
            int t1 = 0;
            int t2 = 1;
            int r1 = baseN;
            int r2 = number;

            while (r2 != 0)
            {
                int q = r1 / r2;
                int temp = r2;
                r2 = r1 - q * r2;
                r1 = temp;

                temp = t2;
                t2 = t1 - q * t2;
                t1 = temp;
            }

            if (r1 > 1)
                return -1;

            if (t1 < 0)
                t1 += originalBaseN;

            return t1;
        }
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


        

    }
}
