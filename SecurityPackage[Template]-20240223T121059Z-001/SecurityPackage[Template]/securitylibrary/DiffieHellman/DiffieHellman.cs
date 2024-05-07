using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

      public  int power(int f, int s, int sf)
        {
            //throw new NotImplementedException();
            int res = 1;
            for(int i=0;i<s;i++)
            {
                res = (res * f) % sf;
            }
            return res;

        }

       public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            //throw new NotImplementedException();
           int ya = power(alpha, xa, q);
           int yb = power(alpha, xb, q);
           int k1 = power(yb, xa, q);
           int k2 = power(ya, xb, q);

            List<int> keys = new List<int>();
            keys.Add(k1);
            keys.Add(k2);

            return keys;

            
        }
    }
}